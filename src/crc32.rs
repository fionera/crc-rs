use crate::table::crc32_table;

use super::{Algorithm, Crc, Digest};

impl Crc<u32> {
    pub const fn new(algorithm: &'static Algorithm<u32>) -> Self {
        let table = crc32_table(algorithm.width, algorithm.poly, algorithm.refin);
        Self { algorithm, table }
    }

    pub const fn checksum(&self, bytes: &[u8]) -> u32 {
        let mut crc = self.init(self.algorithm.init);
        crc = self.update(crc, bytes);
        self.finalize(crc)
    }

    const fn init(&self, initial: u32) -> u32 {
        if self.algorithm.refin {
            initial.reverse_bits() >> (32u8 - self.algorithm.width)
        } else {
            initial << (32u8 - self.algorithm.width)
        }
    }

    const fn table_entry(&self, index: u32) -> u32 {
        self.table[(index & 0xFF) as usize]
    }

    const fn update(&self, mut crc: u32, bytes: &[u8]) -> u32 {
        let mut i = 0;
        while i < bytes.len() {
            let b: u32;

            #[cfg(target_arch = "bpf")]
            {
                let v = core::hint::black_box(bytes[i] as i32);
                if v < u8::MIN as i32 || v > u8::MAX as i32 {
                    return 0;
                }
                b = v as u32;
            }

            #[cfg(not(target_arch = "bpf"))]
            {
                b = bytes[i] as u32;
            }

            let table_index: u32;
            if self.algorithm.refin {
                table_index = (crc >> 24) ^ b as u32;
            } else {
                table_index = crc ^ b as u32;
            }

            crc = self.table_entry(table_index) ^ (crc << 8);
            i += 1;
        }

        crc
    }

    const fn finalize(&self, mut crc: u32) -> u32 {
        if self.algorithm.refin ^ self.algorithm.refout {
            crc = crc.reverse_bits();
        }
        if !self.algorithm.refout {
            crc >>= 32u8 - self.algorithm.width;
        }
        crc ^ self.algorithm.xorout
    }

    pub const fn digest(&self) -> Digest<u32> {
        self.digest_with_initial(self.algorithm.init)
    }

    /// Construct a `Digest` with a given initial value.
    ///
    /// This overrides the initial value specified by the algorithm.
    /// The effects of the algorithm's properties `refin` and `width`
    /// are applied to the custom initial value.
    pub const fn digest_with_initial(&self, initial: u32) -> Digest<u32> {
        let value = self.init(initial);
        Digest::new(self, value)
    }
}

impl<'a> Digest<'a, u32> {
    const fn new(crc: &'a Crc<u32>, value: u32) -> Self {
        Digest { crc, value }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.value = self.crc.update(self.value, bytes);
    }

    pub const fn finalize(self) -> u32 {
        self.crc.finalize(self.value)
    }
}
