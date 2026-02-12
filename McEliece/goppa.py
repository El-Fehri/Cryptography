from sage.all import GF, codes, vector, matrix, PolynomialRing
import itertools


class Goppa:
    def __init__(self, m, t):
        self.m = m
        self.t = t
        self.F = GF(2**m, name='a')
        self.R = self.F['x']
        self.x = self.R.gen()
    
    def gen(self):
        while True:
            g = self.R.random_element(degree=self.t)
            if g.is_irreducible():
                break
        g = g.monic()
        L = [a for a in self.F.list() if g(a) != 0]
        C = codes.GoppaCode(g, L)
        self.g = g
        self.L = L
        self.C = C
        self.n = len(L)
        self.k = C.dimension()
        return C
    
    def compute_syndrome_simple(self, r):
        # Create parity check matrix H
        n = self.n
        t = self.t
        H = matrix(self.F, t, n)
        
        for i in range(t):
            for j in range(n):
                H[i, j] = self.L[j]**i / self.g(self.L[j])
        
        # Convert r to field elements for multiplication
        r_field = vector(self.F, [self.F(int(b)) for b in r])
        
        # Syndrome s = H * r^T
        return H * r_field


class SimpleDecoder:
    
    def __init__(self, goppa):
        self.goppa = goppa
        self.n = goppa.n
        self.t = goppa.t
    
    def decode(self, y):
        # Compute syndrome
        s = self.goppa.compute_syndrome_simple(y)
        
        # If syndrome is zero, y is already a codeword
        if all(coord == 0 for coord in s):
            return y
        
        # Brute force search for error pattern
        for weight in range(1, self.t + 1):
            for positions in itertools.combinations(range(self.n), weight):
                # Create error vector
                e = vector(GF(2), self.n)
                for pos in positions:
                    e[pos] = 1
                
                # Compute syndrome for this error
                e_s = self.goppa.compute_syndrome_simple(e)
                
                if e_s == s:
                    # Found error: correct it
                    return vector(GF(2), [y[i] + e[i] for i in range(self.n)])
        
        return None