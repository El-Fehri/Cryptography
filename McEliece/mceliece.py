from goppa import Goppa, SimpleDecoder
from sage.all import GF, random_matrix, vector, matrix
from helpers import Helpers
import random


class McEliece:
    def __init__(self, m, t):
        self.m = m
        self.t = t
        self.goppa = Goppa(m, t)
        self.pk = None
        self.sk = None
        self.n = None
        self.k = None
    
    def keyGen(self, C):
        # Generate code
        C = self.goppa.gen()
        G = C.generator_matrix()
        n, k = G.ncols(), G.nrows()
        self.n = n
        self.k = k
        
        print(f"Parameters: n={n}, k={k}, t={self.t}")
        
        # Make sure G has full rank
        if G.rank() != k:
            print("Warning: G doesn't have full rank")
            # Take row space basis
            G = G.row_space().basis_matrix()
        
        # Generate random invertible S
        while True:
            S = random_matrix(GF(2), k)
            if S.rank() == k:
                break
        
        # Generate random permutation P
        perm = list(range(n))
        random.shuffle(perm)
        P = matrix(GF(2), n, n)
        for i in range(n):
            P[i, perm[i]] = 1
        
        # Public key
        Gp = S * G * P
        
        # Private key
        self.sk = {
            'S': S,
            'S_inv': S.inverse(),
            'G': G,
            'P': P,
            'P_inv': P.inverse(),
            'g': self.goppa.g,
            'L': self.goppa.L,
            't': self.t,
            'n': n,
            'k': k,
            'perm': perm
        }
        
        self.pk = {'Gp': Gp, 'n': n, 'k': k, 't': self.t}
        
        return self.pk, self.sk
    
    def encrypt(self, m_vec, pk=None):
        if pk is None:
            pk = self.pk
        
        Gp = pk['Gp']
        n = pk['n']
        t = pk['t']
        k = pk['k']
        
        # Make sure message has correct length
        if len(m_vec) != k:
            m_vec = vector(GF(2), list(m_vec)[:k])
            if len(m_vec) < k:
                m_vec = vector(GF(2), list(m_vec) + [0] * (k - len(m_vec)))
        
        # Generate error (ALWAYS with weight t)
        e = Helpers.random_error_vector(n, t)
        
        # Encrypt
        c = m_vec * Gp + e
        
        return c
    
    def decrypt(self, c_vec, sk=None):
        if sk is None:
            sk = self.sk
        
        n = sk['n']
        k = sk['k']
        
        # Step 1: Remove permutation
        P_inv = sk['P_inv']
        y = c_vec * P_inv
        
        # Step 2: Decode to find m' where y = m' * G + e'
        decoder = SimpleDecoder(self.goppa)
        codeword = decoder.decode(y)
        
        if codeword is None:
            print("Decoding failed!")
            return None
        
        # Step 3: Since G may not be systematic, we need to solve for m'
        # codeword = m' * G
        # We need to find m' such that m' * G = codeword
        
        G = sk['G']
        
        # Solve the linear system: m' * G = codeword
        # This is equivalent to: G^T * (m')^T = codeword^T
        A = G.transpose()
        b = codeword
        
        try:
            # Solve for m'
            m_prime = A.solve_right(b)
        except:
            print("Cannot solve for m' - G may not have full rank")
            return None
        
        # Step 4: Remove scrambling
        S_inv = sk['S_inv']
        m = m_prime * S_inv
        
        return m