use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use aleo_stratum::message::StratumMessage;
use ansi_term::Colour::{Cyan, Green, Red};
use anyhow::Result;
use json_rpc_types::Id;
use rand::thread_rng;
use rayon::{ThreadPool, ThreadPoolBuilder};
// use snarkvm::{
//     dpc::{testnet2::Testnet2, Network, PoSWCircuit, PoSWError, PoSWProof},
//     utilities::{FromBytes, ToBytes, UniformRand},
// };

//use snarkvm_dpc::{posw::PoSWCircuit, testnet2::Testnet2, BlockTemplate, Network, PoSWScheme};
use snarkvm_utilities::Uniform;

use snarkvm::{
    dpc::{testnet2::Testnet2, Network, PoSWCircuit, PoSWError, PoSWProof, BlockTemplate, PoSWScheme},
    utilities::{FromBytes, ToBytes, UniformRand},
};


use snarkvm_algorithms::{MerkleParameters, CRH, SNARK};
use tokio::{sync::mpsc, task};
use tracing::{debug, error, info};

pub struct Prover {
    thread_pools: Arc<Vec<Arc<ThreadPool>>>,
    cuda: Option<Vec<i16>>,
    cuda_jobs: Option<u8>,
    sender: Arc<mpsc::Sender<ProverEvent>>,
    terminator: Arc<AtomicBool>,
    total_proofs: Arc<AtomicU32>,
}

#[allow(clippy::large_enum_variant)]
pub enum ProverEvent {
    NewTarget(u64),
    NewWork(u32, String, Vec<String>),
    Result(bool, Option<String>),
}

impl Prover {
    pub async fn init(
        threads: u16,
        cuda: Option<Vec<i16>>,
        cuda_jobs: Option<u8>,
        pool_threads:  u16,
        pool_count: u16,
    ) -> Result<Arc<Self>> {
        let mut thread_pools: Vec<Arc<ThreadPool>> = Vec::new();
        // let pool_count;
        // let pool_threads;
        // if threads % 12 == 0 {
        //     pool_count = threads / 12;
        //     pool_threads = 12;
        // } else if threads % 10 == 0 {
        //     pool_count = threads / 10;
        //     pool_threads = 10;
        // } else if threads % 8 == 0 {
        //     pool_count = threads / 8;
        //     pool_threads = 8;
        // } else {
        //     pool_count = threads / 6;
        //     pool_threads = 6;
        // }
        if cuda.is_none() {
            for index in 0..pool_count {
                let pool = ThreadPoolBuilder::new()
                    .stack_size(8 * 1024 * 1024)
                    .num_threads(pool_threads as usize)
                    .thread_name(move |idx| format!("ap-cpu-{}-{}", index, idx))
                    .build()?;
                thread_pools.push(Arc::new(pool));
            }
            info!(
                "Created {} cpu-prover thread pools with {} threads each",
                thread_pools.len(),
                pool_threads
            );
        } else {
            // let total_jobs = cuda_jobs.unwrap_or(1) * cuda.clone().unwrap().len() as u8;
            for index in 0..pool_count {
                let pool = ThreadPoolBuilder::new()
                    .stack_size(8 * 1024 * 1024)
                    .num_threads(pool_threads as usize)
                    .thread_name(move |idx| format!("ap-cuda-{}-{}", index, idx))
                    .build()?;
                thread_pools.push(Arc::new(pool));
            }
            info!("Created {} cuda-prover ThreadPools with {} threads each", thread_pools.len(), pool_threads);
        }

        let (sender, mut receiver) = mpsc::channel(1024);
        let terminator = Arc::new(AtomicBool::new(false));
        let prover = Arc::new(Self {
            thread_pools: Arc::new(thread_pools),
            cuda,
            cuda_jobs,
            sender: Arc::new(sender),
            terminator,
            total_proofs: Default::default(),
        });

        let p = prover.clone();
        let _ = task::spawn(async move {

            let mut number = 1;
            while number != 2 {
                println!("{}", number);
                p.new_work(number).await;
                number += 1;
            }

            info!("task::spawn new_work num: [{}]", number-1);
            
            // while let Some(msg) = receiver.recv().await {


            //     match msg {
            //         ProverEvent::NewTarget(target) => {
            //             p.new_target(target);
            //         }
            //         ProverEvent::NewWork(height, block_header_root, hashed_leaves) => {
            //             p.new_work(
            //                 height,
            //             )
            //             .await;
            //         }
            //         ProverEvent::Result(success, error) => {
            //             p.result(success, error).await;
            //         }
            //     }
            // }
        });
        debug!("Created prover message handler");

        let terminator = prover.terminator.clone();

        task::spawn(async move {
            let mut counter = false;
            loop {
                if terminator.load(Ordering::SeqCst) {
                    if counter {
                        debug!("Long terminator detected, resetting");
                        terminator.store(false, Ordering::SeqCst);
                        counter = false;
                    } else {
                        counter = true;
                    }
                } else {
                    counter = false;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        debug!("Created prover terminator guard");

        let total_proofs = prover.total_proofs.clone();
        task::spawn(async move {
            fn calculate_proof_rate(now: u32, past: u32, interval: u32) -> Box<str> {
                if interval < 1 {
                    return Box::from("---");
                }
                if now <= past || past == 0 {
                    return Box::from("---");
                }
                let rate = (now - past) as f64 / (interval * 60) as f64;
                Box::from(format!("{:.2}", rate))
            }
            let mut log = VecDeque::<u32>::from(vec![0; 60]);
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let proofs = total_proofs.load(Ordering::SeqCst);
                log.push_back(proofs);
                let m1 = *log.get(59).unwrap_or(&0);
                let m5 = *log.get(55).unwrap_or(&0);
                let m15 = *log.get(45).unwrap_or(&0);
                let m30 = *log.get(30).unwrap_or(&0);
                let m60 = log.pop_front().unwrap_or_default();
                info!(
                    "{}",
                    Cyan.normal().paint(format!(
                        "Total proofs: {} (1m: {} p/s, 5m: {} p/s, 15m: {} p/s, 30m: {} p/s, 60m: {} p/s)",
                        proofs,
                        calculate_proof_rate(proofs, m1, 1),
                        calculate_proof_rate(proofs, m5, 5),
                        calculate_proof_rate(proofs, m15, 15),
                        calculate_proof_rate(proofs, m30, 30),
                        calculate_proof_rate(proofs, m60, 60),
                    ))
                );
            }
        });
        debug!("Created proof rate calculator");

        Ok(prover)
    }

    pub fn sender(&self) -> Arc<mpsc::Sender<ProverEvent>> {
        self.sender.clone()
    }

    async fn result(&self, success: bool, msg: Option<String>) {
        info!("Share accepted");
    }

    fn new_target(&self, difficulty_target: u64) {
        info!("New difficulty target: {}", u64::MAX / difficulty_target);
    }

    async fn new_work(
        &self,
        height: u32,
    ) {
        info!("Received new work: block {}", height,);
        let terminator = self.terminator.clone();
        let thread_pools = self.thread_pools.clone();
        let total_proofs = self.total_proofs.clone();
        let cuda = self.cuda.clone();
        let cuda_jobs = self.cuda_jobs;

        task::spawn(async move {
            terminator.store(true, Ordering::SeqCst);
            while terminator.load(Ordering::SeqCst) {
                // Wait until the prover terminator is set to false.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            let _ = task::spawn(async move {
                let mut joins = Vec::new();
                if let Some(cuda) = cuda {
                    let mut tp_num = 0;
                    let cuda_len = cuda.len();

                    info!("threadpool len {}", thread_pools.len());

                    for gpu_index in cuda {
                        info!("gpu_index {}, cuda_len {}", gpu_index, cuda_len);
                        for job_index in 0..cuda_jobs.unwrap_or(1) {
                            info!("job_index {} cuda_jobs {}", job_index, cuda_jobs.unwrap());
                            let tp_index = gpu_index as usize * cuda_jobs.unwrap_or(1) as usize + job_index as usize;
                            info!("tp_index {}", tp_index);
                            let tp = thread_pools
                                .get(tp_index)
                                .unwrap();
                            info!("Spawning CUDA thread on GPU {} job {}", gpu_index, job_index,);
                            let terminator = terminator.clone();
                            let total_proofs = total_proofs.clone();
                            let tp = tp.clone();

                            info!("Spawning task for threadpool {}", tp_num);
                            tp_num += 1;

                            joins.push(task::spawn(async move {
                                while !terminator.load(Ordering::SeqCst) {
                                    let terminator = terminator.clone();
                                    let block_height = height;
                                    let tp = tp.clone();
                                    let tp_num = tp_num.clone();
                                    let gpu_index = gpu_index.clone();
                                    let job_index = job_index.clone();
                    
                                    // tokio::time::sleep(Duration::from_secs(3)).await;
                                    if let Ok(proof) = task::spawn_blocking(move || {
                                        tp.install(|| {
                                            info!("Doing task on threadpool {} weight {} gpu_index {} job_index {}, cuda", tp_num, block_height, gpu_index, job_index);

                                            let mut rng = thread_rng();
    
                                            // Construct the block template.
                                            info!("Doing task on threadpool {} height {} gpu_index {} job_index {}, cuda   ---------   genesis_block", tp_num, block_height, gpu_index, job_index);
                                            let block = Testnet2::genesis_block();
                                            let block_template = BlockTemplate::new(
                                                block.previous_block_hash(),
                                                block.height(),
                                                block.timestamp(),
                                                block.difficulty_target(),
                                                block.cumulative_weight(),
                                                block.previous_ledger_root(),
                                                block.transactions().clone(),
                                                block
                                                    .to_coinbase_transaction()
                                                    .unwrap()
                                                    .to_records()
                                                    .next()
                                                    .unwrap(),
                                            );
    
                                            info!("Doing task on threadpool {} height {} gpu_index {} job_index {}, cuda   ---------   setup circuit", tp_num, block_height, gpu_index, job_index);
                                            // Instantiate the circuit.
                                            let mut circuit =
                                            PoSWCircuit::<Testnet2>::new(&block_template, Uniform::rand(&mut rng)).unwrap();
    
                                            // Run one iteration of PoSW.
                                            info!("Doing task on threadpool {} height {} gpu_index {} job_index {}, cuda   ---------   posw proof", tp_num, block_height, gpu_index, job_index);
                                            let proof = Testnet2::posw()
                                            .prove_once_unchecked(&mut circuit, &block_template, &terminator, &mut rng, gpu_index)
                                            .unwrap();
                                            // Check if the updated proof is valid.
                                            // info!("Doing task on threadpool {} height {}, cpu   ---------   posw verify", tp_num, block_height,);
                                            // if !Testnet2::posw().verify(
                                            //     block_template.difficulty_target(),
                                            //     &circuit.to_public_inputs(),
                                            //     &proof,
                                            // ) {
                                            //     panic!("proof verification failed, contestant disqualified");
                                            // }

                                            info!("Doing task on threadpool {} height {} gpu_index {} job_index {}, cuda   ---------   prove finish", tp_num, block_height, gpu_index, job_index);
                                        });
                                        
                                        height
                                    })
                                    .await
                                    {
                                        info!("Doing task on threadpool {} weight {} gpu_index {} job_index {}, cuda await", tp_num, block_height, gpu_index, job_index);
                                        total_proofs.fetch_add(1, Ordering::SeqCst);
                                    }
                                }
                            }));
                        }
                    }
                } else {
                    let mut tp_num = 0;
                    for tp in thread_pools.iter() {
                        let terminator = terminator.clone();
                        let total_proofs = total_proofs.clone();
                        let tp = tp.clone();

                        info!("Spawning task for threadpool {} thread_pools {}, cpu", tp_num, thread_pools.len());
                        
                        joins.push(task::spawn(async move {
                            while !terminator.load(Ordering::SeqCst) {
                                let terminator = terminator.clone();
                                let tp = tp.clone();
                                let block_height = height;
                                let tp_num = tp_num.clone();

                                // tokio::time::sleep(Duration::from_secs(3)).await;
       
                                // if let Ok(Ok(proof)) = task::spawn_blocking(move || {
                                if let Ok(proof) = task::spawn_blocking(move || {
                                    tp.install(|| {
                                        info!("Doing task on threadpool {} height {}, cpu", tp_num, block_height,);

                                        let mut rng = thread_rng();

                                        // Construct the block template.
                                        info!("Doing task on threadpool {} height {}, cpu   ---------   genesis_block", tp_num, block_height,);
                                        let block = Testnet2::genesis_block();
                                        let block_template = BlockTemplate::new(
                                            block.previous_block_hash(),
                                            block.height(),
                                            block.timestamp(),
                                            block.difficulty_target(),
                                            block.cumulative_weight(),
                                            block.previous_ledger_root(),
                                            block.transactions().clone(),
                                            block
                                                .to_coinbase_transaction()
                                                .unwrap()
                                                .to_records()
                                                .next()
                                                .unwrap(),
                                        );


                                        info!("Doing task on threadpool {} height {}, cpu   ---------   setup circuit", tp_num, block_height,);
                                        // Instantiate the circuit.
                                        let mut circuit =
                                        PoSWCircuit::<Testnet2>::new(&block_template, Uniform::rand(&mut rng)).unwrap();

                                        // Run one iteration of PoSW.
                                        info!("Doing task on threadpool {} height {}, cpu   ---------   posw proof", tp_num, block_height,);
                                        let proof = Testnet2::posw()
                                        .prove_once_unchecked(&mut circuit, &block_template, &terminator, &mut rng, -1)
                                        .unwrap();
                                        // Check if the updated proof is valid.
                                        // info!("Doing task on threadpool {} height {}, cpu   ---------   posw verify", tp_num, block_height,);
                                        // if !Testnet2::posw().verify(
                                        //     block_template.difficulty_target(),
                                        //     &circuit.to_public_inputs(),
                                        //     &proof,
                                        // ) {
                                        //     panic!("proof verification failed, contestant disqualified");
                                        // }

                                        info!("Doing task on threadpool {} height {}, cpu   ---------   prove finish", tp_num, block_height,);
                                    });
                                    height
                                })
                                .await
                                {
                                    info!("Doing task on threadpool {} height {}, cpu await", tp_num, block_height,);
                                    total_proofs.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }));

                        tp_num += 1;
                    }
                }
                futures::future::join_all(joins).await;
                terminator.store(false, Ordering::SeqCst);
            });
        });
    }
}
