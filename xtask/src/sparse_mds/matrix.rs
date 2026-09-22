//! Dense linear algebra over the BN254 scalar field.
//!
//! Only what the sparse-MDS derivation needs: square matrix products,
//! matrix-vector products, transposition and a Gauss-Jordan solver.

use anyhow::anyhow;
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

/// A dense square matrix over `Fr`, stored row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    order: usize,
    data: Vec<Fr>,
}

impl Matrix {
    pub fn zero(order: usize) -> Self {
        Self {
            order,
            data: vec![Fr::zero(); order * order],
        }
    }

    pub fn identity(order: usize) -> Result<Self, anyhow::Error> {
        let mut matrix = Self::zero(order);
        for i in 0..order {
            matrix.set(i, i, Fr::one())?;
        }
        Ok(matrix)
    }

    /// Builds a matrix from a flat row-major slice, as `PoseidonParameters::mds`
    /// stores it.
    pub fn from_flat(entries: &[Fr], order: usize) -> Result<Self, anyhow::Error> {
        let expected = order
            .checked_mul(order)
            .ok_or_else(|| anyhow!("order {order} overflows"))?;
        if entries.len() != expected {
            return Err(anyhow!(
                "flat matrix has {} entries, expected {expected} for order {order}",
                entries.len()
            ));
        }
        Ok(Self {
            order,
            data: entries.to_vec(),
        })
    }

    pub fn order(&self) -> usize {
        self.order
    }

    pub fn as_slice(&self) -> &[Fr] {
        &self.data
    }

    pub fn get(&self, i: usize, j: usize) -> Result<Fr, anyhow::Error> {
        if i >= self.order || j >= self.order {
            return Err(anyhow!(
                "index ({i}, {j}) out of bounds for order {}",
                self.order
            ));
        }
        self.data
            .get(i * self.order + j)
            .copied()
            .ok_or_else(|| anyhow!("matrix data shorter than its order"))
    }

    pub fn set(&mut self, i: usize, j: usize, value: Fr) -> Result<(), anyhow::Error> {
        if i >= self.order || j >= self.order {
            return Err(anyhow!(
                "index ({i}, {j}) out of bounds for order {}",
                self.order
            ));
        }
        let order = self.order;
        let slot = self
            .data
            .get_mut(i * order + j)
            .ok_or_else(|| anyhow!("matrix data shorter than its order"))?;
        *slot = value;
        Ok(())
    }

    pub fn mul(&self, rhs: &Matrix) -> Result<Matrix, anyhow::Error> {
        if self.order != rhs.order {
            return Err(anyhow!(
                "cannot multiply order {} by order {}",
                self.order,
                rhs.order
            ));
        }
        let mut out = Matrix::zero(self.order);
        for i in 0..self.order {
            for j in 0..self.order {
                let mut acc = Fr::zero();
                for k in 0..self.order {
                    acc += self.get(i, k)? * rhs.get(k, j)?;
                }
                out.set(i, j, acc)?;
            }
        }
        Ok(out)
    }

    pub fn mul_vec(&self, vector: &[Fr]) -> Result<Vec<Fr>, anyhow::Error> {
        if vector.len() != self.order {
            return Err(anyhow!(
                "cannot multiply order {} by a vector of length {}",
                self.order,
                vector.len()
            ));
        }
        let mut out = Vec::with_capacity(self.order);
        for i in 0..self.order {
            let mut acc = Fr::zero();
            for (j, value) in vector.iter().enumerate() {
                acc += self.get(i, j)? * *value;
            }
            out.push(acc);
        }
        Ok(out)
    }

    pub fn transpose(&self) -> Result<Matrix, anyhow::Error> {
        let mut out = Matrix::zero(self.order);
        for i in 0..self.order {
            for j in 0..self.order {
                out.set(j, i, self.get(i, j)?)?;
            }
        }
        Ok(out)
    }

    /// Returns the submatrix obtained by dropping the first row and column.
    pub fn minor_00(&self) -> Result<Matrix, anyhow::Error> {
        if self.order == 0 {
            return Err(anyhow!("cannot take the minor of an empty matrix"));
        }
        let mut out = Matrix::zero(self.order - 1);
        for i in 1..self.order {
            for j in 1..self.order {
                out.set(i - 1, j - 1, self.get(i, j)?)?;
            }
        }
        Ok(out)
    }

    /// Embeds `block` as the lower-right submatrix of an identity matrix, so
    /// that the result leaves the first coordinate untouched.
    pub fn from_minor_00(block: &Matrix) -> Result<Matrix, anyhow::Error> {
        let mut out = Matrix::identity(block.order + 1)?;
        for i in 0..block.order {
            for j in 0..block.order {
                out.set(i + 1, j + 1, block.get(i, j)?)?;
            }
        }
        Ok(out)
    }
}

/// Solves `matrix * x = rhs` by Gauss-Jordan elimination.
///
/// Returns an error when `matrix` is singular, which for an MDS matrix and the
/// products derived from it should never happen: every square submatrix of an
/// MDS matrix is invertible by definition.
pub fn solve(matrix: &Matrix, rhs: &[Fr]) -> Result<Vec<Fr>, anyhow::Error> {
    let order = matrix.order();
    if rhs.len() != order {
        return Err(anyhow!(
            "right-hand side of length {} does not match order {order}",
            rhs.len()
        ));
    }

    // Augmented matrix: each row is `order` coefficients followed by the
    // right-hand side entry.
    let mut rows: Vec<Vec<Fr>> = Vec::with_capacity(order);
    for i in 0..order {
        let mut row = Vec::with_capacity(order + 1);
        for j in 0..order {
            row.push(matrix.get(i, j)?);
        }
        row.push(
            *rhs.get(i)
                .ok_or_else(|| anyhow!("right-hand side shorter than its length"))?,
        );
        rows.push(row);
    }

    for col in 0..order {
        let pivot = (col..order)
            .find(|row_index| {
                rows.get(*row_index)
                    .and_then(|row| row.get(col))
                    .is_some_and(|value| !value.is_zero())
            })
            .ok_or_else(|| anyhow!("matrix is singular at column {col}"))?;
        rows.swap(col, pivot);

        let pivot_value = *rows
            .get(col)
            .and_then(|row| row.get(col))
            .ok_or_else(|| anyhow!("missing pivot at ({col}, {col})"))?;
        let pivot_inverse = pivot_value
            .inverse()
            .ok_or_else(|| anyhow!("pivot at ({col}, {col}) is not invertible"))?;

        let pivot_row = {
            let row = rows
                .get_mut(col)
                .ok_or_else(|| anyhow!("missing pivot row {col}"))?;
            for value in row.iter_mut() {
                *value *= pivot_inverse;
            }
            row.clone()
        };

        for (row_index, row) in rows.iter_mut().enumerate() {
            if row_index == col {
                continue;
            }
            let factor = *row
                .get(col)
                .ok_or_else(|| anyhow!("missing entry at ({row_index}, {col})"))?;
            if factor.is_zero() {
                continue;
            }
            for (value, pivot_value) in row.iter_mut().zip(pivot_row.iter()) {
                *value -= factor * *pivot_value;
            }
        }
    }

    rows.iter()
        .enumerate()
        .map(|(i, row)| {
            row.get(order)
                .copied()
                .ok_or_else(|| anyhow!("missing solution entry in row {i}"))
        })
        .collect()
}
