from sage.all import GF

class GoppaCode:
    def __init__(self, m, t):
        self.m = m
        self.t = t
        self.F = GF(2**m, name='a')
        self.R = self.F['x']
        self.x = self.R.gen()
        # Goppa polynomial of degree t
        self.g = self.R.irreducible_element(t).monic()
        # Support set: all field elements where g(alpha) != 0
        self.L = [alpha for alpha in self.F if self.g(alpha) != 0]

    def calculate_syndrome(self, y):
        """Calculate syndrome S(x) = sum(y_i / (x - L[i])) mod g(x)"""
        syndrome = self.R(0)
        
        for i in range(len(y)):
            if i < len(self.L) and y[i] != 0:
                try:
                    # Calculate 1 / (x - L[i]) mod g(x)
                    denom = self.x - self.L[i]
                    inv_denom = denom.inverse_mod(self.g)
                    syndrome = (syndrome + inv_denom) % self.g
                except:
                    continue
        
        return syndrome

    def sigma(self, s):
        """Compute error locator polynomial using Patterson algorithm"""
        if s == 0:
            return self.x  # No errors detected
        
        try:
            # Step 1: Find h such that h*s ≡ 1 (mod g)
            h = s.inverse_mod(self.g)
        except:
            return self.x  # Return x for no errors case
        
        if h == 1:
            # Special case: σ(x) = x
            return self.x
        
        # Step 2: Find d such that d^2 ≡ h + x (mod g)
        target = (h + self.x) % self.g
        
        # Try to find square root
        d = self.find_square_root_mod(target, self.g)
        if d is None:
            print(f"Could not find square root of {target} mod {self.g}, returning x")
            return self.x
        
        # Step 3: Apply EEA to find a, b such that d*b ≡ a (mod g) with deg(a), deg(b) minimal
        a, b = self.extended_euclidean_for_patterson(d, self.g)
        
        # Step 4: σ(x) = a^2 + x*b^2
        # IMPORTANT: Do NOT reduce modulo g here! Keep in full polynomial ring
        sigma = a**2 + self.x * b**2
        return sigma

    def find_square_root_mod(self, target, g):
        """Find d such that d^2 ≡ target (mod g)"""
        R = g.parent()
        deg_g = g.degree()
        
        # For small degrees, try all possibilities
        if deg_g <= 6:  # Increased to handle slightly larger degrees
            from itertools import product
            F = g.base_ring()
            for degree in range(deg_g):
                for coeffs in product(F, repeat=degree+1):
                    d_candidate = R(list(coeffs))
                    if (d_candidate**2 - target) % g == 0:
                        return d_candidate
        else:
            # Try Sage's sqrt if possible
            try:
                sqrt_result = target.sqrt()
                if (sqrt_result**2 - target) % g == 0:
                    return sqrt_result
            except:
                pass
        
        return None

    def extended_euclidean_for_patterson(self, d, g):
        """Extended Euclidean Algorithm to find a, b such that d*b ≡ a (mod g) with minimal degrees"""
        R = g.parent()
        
        # This means a ≡ 0 (mod g), so smallest a is 0, and smallest b is 1
        if d == 0:
            return R(0), R(1)
        
        # General case: apply EEA to find minimal a, b
        r0, r1 = g, d % g
        s0, s1 = R(1), R(0)  # coefficients for g
        t0, t1 = R(0), R(1)  # coefficients for d
        
        # Continue until remainder has degree <= deg(g)/2
        threshold = g.degree() // 2
        
        while r1 != 0 and r1.degree() > threshold:
            try:
                q = r0 // r1
                r0, r1 = r1, r0 - q*r1
                s0, s1 = s1, s0 - q*s1
                t0, t1 = t1, t0 - q*t1
            except:
                break
        
        # At this stage: g*s1 + d*t1 = r1
        # So: d*t1 = r1 - g*s1 ≡ r1 (mod g)
        # Therefore: a = r1, b = t1
        a = r1 % g  
        b = t1 % g  
        
        return a, b

    def construct_E(self, sigma_x):
        """Find error positions: E = {i | σ(L[i]) = 0}"""
        E = []
        for i in range(len(self.L)):
            try:
                # Evaluate sigma at L[i] in the field directly
                eval_result = sigma_x.substitute({self.x: self.L[i]})
                if eval_result == 0:
                    E.append(i)
            except:
                continue
        return E
    
    def construct_error_vector(self, E, length):
        """Construct error vector from error positions"""
        error_vector = [0] * length
        for i in E:
            if i < length:
                error_vector[i] = 1
        return error_vector
    
    def correct_errors(self, received):
        """Main Patterson decoding function"""
        s = self.calculate_syndrome(received)
        
        if s == 0:
            # No errors detected
            return received
        
        sigma_x = self.sigma(s)
        E = self.construct_E(sigma_x)
        error_vector = self.construct_error_vector(E, len(received))
        
        # The corrected word is received XOR error_vector
        corrected = [(received[i] + error_vector[i]) % 2 for i in range(len(received))]
        return corrected
    
    def generate_valid_codeword(self):
        n = len(self.L)
        
        # Start with a random binary vector
        codeword = [random.randint(0, 1) for _ in range(n)]
        
        # Calculate its syndrome
        syndrome = self.calculate_syndrome(codeword)
        
        if syndrome == 0:
            # Already a valid codeword
            return codeword
        return [0] * n
    
    def get_info(self):
        """Return information about the code"""
        return {
            'field_size': 2**self.m,
            'dimension': len(self.L) - self.t,  
            'length': len(self.L),
            'degree_t': self.t,
            'goppa_polynomial': self.g,
            'support_set_size': len(self.L)
        }

    def get_parameters(self):
        """Return the parameters m, n, t"""
        n = len(self.L)  # Length of the code
        # For approximate dimension k, it's roughly n - m*t for Goppa codes
        k = len(self.L) - self.t  # Simplified approximation
        t = self.t
        return n, k, t
import random