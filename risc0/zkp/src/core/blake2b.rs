// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A Blake2b HashSuite.
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use blake2::{digest::{Update, VariableOutput}, VarBlake2b};

use risc0_core::field::baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem};
use risc0_core::field::ExtElem;

use crate::core::config::{ConfigHash, ConfigRng};

use super::config::HashSuite;
use super::digest::Digest;

/// Hash function trait.
pub trait Blake2bHasher {
    /// A function producing a hash from a list of u8.
    fn blake2b<T: AsRef<[u8]>>(data: T) -> [u8; 32];
}

/// Implementation of blake2b using CPU.
pub struct Blake2bImplCpu;

/// Type alias for Blake2b HashSuite using CPU.
pub type HashSuiteBlake2bCpu = HashSuiteBlake2b<Blake2bImplCpu>;

impl Blake2bHasher for Blake2bImplCpu {
    fn blake2b<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut result = [0; 32];
        let mut hasher = VarBlake2b::new(32).expect("should create hasher");

        hasher.update(data);
        hasher.finalize_variable(|slice| {
            result.copy_from_slice(slice);
        });
        result
    }
}

/// Blake2b HashSuite.
/// We are using a generic hasher to allow for different implementations.
pub struct HashSuiteBlake2b<T: Blake2bHasher> {
    hasher: PhantomData<T>,
}

impl<T: Blake2bHasher> HashSuite<BabyBear> for HashSuiteBlake2b<T> {
    type Hash = ConfigHashBlake2b<T>;
    type Rng = Blake2bRng<T>;
}

/// Blake2b ConfigHash.
pub struct ConfigHashBlake2b<T: Blake2bHasher> {
    hasher: PhantomData<T>,
}

impl<T: Blake2bHasher> ConfigHash<BabyBear> for ConfigHashBlake2b<T> {
    type DigestPtr = Box<Digest>;

    fn hash_pair(a: &Digest, b: &Digest) -> Self::DigestPtr {
        let concat = [a.as_bytes().as_ref(), b.as_bytes()].concat();
        Box::new(Digest::from(T::blake2b(concat)))
    }

    fn hash_elem_slice(slice: &[BabyBearElem]) -> Self::DigestPtr {
        let mut data = Vec::<u8>::new();
        for el in slice {
            data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
        }
        Box::new(Digest::from(T::blake2b(data)))
    }

    fn hash_ext_elem_slice(slice: &[BabyBearExtElem]) -> Self::DigestPtr {
        let mut data = Vec::<u8>::new();
        for ext_el in slice {
            for el in ext_el.subelems() {
                data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
            }
        }
        Box::new(Digest::from(T::blake2b(data)))
    }
}

/// Blake2b-based random number generator.
pub struct Blake2bRng<T: Blake2bHasher> {
    current: [u8; 32],
    hasher: PhantomData<T>,
}

impl<T: Blake2bHasher> ConfigRng<BabyBear> for Blake2bRng<T> {
    fn new() -> Self {
        Self {
            current: [0; 32],
            hasher: Default::default(),
        }
    }

    fn mix(&mut self, val: &Digest) {
        let concat = [self.current.as_ref(), val.as_bytes()].concat();
        self.current = T::blake2b(concat);
    }

    fn random_u32(&mut self) -> u32 {
        let next = T::blake2b(self.current);
        self.current = next;

        ((next[0] as u32) << 24) +
            ((next[1] as u32) << 16) +
            ((next[2] as u32) << 8) +
            ((next[3] as u32) << 0)
    }

    fn random_elem(&mut self) -> BabyBearElem {
        BabyBearElem::new(self.random_u32())
    }

    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        BabyBearExtElem::new(
            self.random_elem(),
            self.random_elem(),
            self.random_elem(),
            self.random_elem(),
        )
    }
}
