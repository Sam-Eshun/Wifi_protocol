from tno.mpc.encryption_schemes.dgk import DGK
from phe import paillier
import random
from typing import List
import secrets
import pyhash
from bitarray import bitarray
import hashlib

def encrypt_rss_values(V_u, pk_u):
    # create a random vector of 10 values in the range [-100, 0]
     # Generate user's own public key
    pk_u = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1)
    #pk_u, sk_u = DGK.generate_keypair(2048)
    #pk_u, sk_u = dgk.generate()
    #V_u = [random.randint(-100, 0) for _ in range(10)]
    C = []
    phi = sum([r**2 for r in V_u])
    enc_phi = pk_u.encrypt(phi)
    for r in V_u:
        c_i = pk_u.encrypt(-2 * r)
        C.append((c_i, enc_phi))
    return C
# Send encrypted RSS values to the SP
#    n = len(C)
 #   encrypted_rss_values = []
  #  for i in range(n):
   #     c_x_bits = C[i][0]
    #    encrypted_rss_values.append(c_x_bits)
        
    #return encrypted_rss_values
# Example usage
V_u = [random.randint(-100, 0) for _ in range(10)]
pk_u = "User's public key"
encrypted_rss_values = encrypt_rss_values(V_u, pk_u)
print(encrypted_rss_values)



#def encrypted_euclidean_distance(user_data, database):

def euclidean_distance(user_pubkey: DGK.PublicKey, C: List[tuple], V: List[int], j: int) -> DGK.Ciphertext:

     # Initialize DGK
    dgk = DGK.from_public_key(user_pubkey)
    n = len(V)
    #generate public and private key pair
    SP_public_key, SP_private_key = paillier.generate_keypair(2048)
    # Encrypt V using user's public key
    V_enc = [user_pubkey.encrypt(v**2) for v in V]

     # Generate random j1 and j2
    j1, j2 = secrets.randbits(128), secrets.randbits(128)

    # Use provided enc_phi as j3
    j3 = C[-1][1]

    # Calculate enc_phi_j1 = enc(sum(V_i^2))
    enc_phi_j1 = user_pubkey.encrypt(0)
    for i in range(n):
        enc_phi_j1 += V_enc[i]
    enc_phi_j1 = user_pubkey.homomorphic_add_constant(enc_phi_j1, j1)
   

    # Calculate enc_phi_j2 = prod_i(c_i^(v_ij))
    enc_phi_j2 = user_pubkey.encrypt(1)
    for i, c in enumerate(C):
        c_i, enc_c = c
        enc_phi_j2 = user_pubkey.homomorphic_multiply(enc_phi_j2, user_pubkey.encrypt(c_i)**V[i][j])
    enc_phi_j2 = user_pubkey.homomorphic_add_constant(enc_phi_j2, j2)

    # Calculate enc_delta
    enc_delta = user_pubkey.homomorphic_multiply(enc_phi_j1, enc_phi_j2)
    enc_delta = user_pubkey.homomorphic_multiply(enc_delta, j3)
    return enc_delta

    # Blind (mask) enc_delta with a random value gamma
    gamma = secrets.randbits(n)
    enc_gamma = SP_public_key.encrypt(gamma)
    enc_masked_delta = SP_public_key.homomorphic_multiply(enc_delta, enc_gamma)
    return enc_masked_delta




def cloud_server_evaluation(enc_masked_delta, garbled_circuit, pk_u, gamma):
    # Step 1: Decrypt the encrypted masked euclidean distances using the user's DGK private key
    #pk_u = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1)
    masked_distances = []
    for  distance in enc_masked_delta:
        masked_distances.append(pk_u.dgk_decrypt( enc_masked_delta))
    #decrypted_distances = [pk_u.dgk_decrypt(distance) for distance in masked_distances]
    

    # Step 2: Use oblivious transfer to select the correct garbled circuit input keys
    garbled_inputs = []
    for i in range(len(masked_distances)):
        garbled_inputs.append(ot_1_out_of_2(masked_distances[i], garbled_circuit[i]))
    
    # Step 3: Evaluate the garbled circuit to obtain the garbled output wires
    garbled_output_wires = []
    for j in range(len(garbled_circuit.output_wires)):
        input_wire_0, input_wire_1 = garbled_inputs[garbled_circuit.input_wire_indices[j][0]], garbled_inputs[garbled_circuit.input_wire_indices[j][1]]
        garbled_output_wire = garbled_circuit.evaluate_gate(j, input_wire_0, input_wire_1)
        
        # Step 5: Use conditional swap to compare each garbled output wire with zero and swap it with the corresponding index if it is less than zero
        garbled_output_minus_gamma = garbled_output_wire - gamma
        Output_wire = conditional_swap(garbled_output_minus_gamma < 0, garbled_output_minus_gamma, 0)
        
       
     
    # Step 7: Convert the decrypted garbled output wires into the indices of the euclidean distances
    Output_wire_indices = []
    for output_index in Output_wire:
        Output_wire_indices.append(convert_wire_to_index(Output_wire))
    
    # Return the list of indices
    return Output_wire_indices
   

# user converts the garbled output wire to into plain index
def convert_output_wire(Output_wire_indices):
    D = []
    k = len(Output_wire_indices)
    h = [random.randint(0, 1) for _ in range(k)]
    for j in range(k):
        d_j = Output_wire_indices[j].lsb() ^ h[j]
        D.append(d_j)
    x, y = loc(D)  # assuming loc() is a function defined elsewhere
    return x, y




class User:
    def __init__(self, location):
        self.location = location
        self.num_hash_funcs = 3  # number of hash functions to use
        self.num_bits = 10  # number of bits in the Bloom filter
        self.hash_funcs = [pyhash.fnv1_32(), pyhash.murmur3_32(), pyhash.sdbm()]
        
    def generate_bloom_filter(self):
        # Initialize an empty bit array of size num_bits
        bloom_filter = bitarray(self.num_bits)
        bloom_filter.setall(0)
        
        # Hash the location using num_hash_funcs hash functions
        for i in range(self.num_hash_funcs):
            hash_val = self.hash_funcs[i](self.location.encode('utf-8'))
            
            # Map the hash value to a bit in the Bloom filter
            bit_idx = hash_val % self.num_bits
            
            # Set the bit at the calculated index to 1
            bloom_filter[bit_idx] = 1
            
        return bloom_filter

class Users:
    def __init__(self, location):
            self.location = location
            self.num_hash_funcs = 3  # number of hash functions to use
            self.num_bits = 10  # number of bits in the Bloom filter
            self.hash_funcs = [pyhash.fnv1_32(), pyhash.murmur3_32(), pyhash.sdbm()]

    def generate_spatial_bloom_filter(location, radius, num_bits,self):
        """
        Generate a spatial Bloom filter based on a given location and radius.

        Args:
            location (tuple): A tuple of latitude and longitude coordinates.
            radius (float): The radius around the location to include in the Bloom filter.
            num_bits (int): The number of bits in the Bloom filter.

        Returns:
            bytes: A byte string representing the spatial Bloom filter.
        """
        # Initialize an empty bit array
        bit_array = [0] * num_bits

        # Compute a hash for the location
        location_hash = hashlib.sha256(str(location).encode()).digest()

         # Hash the location using num_hash_funcs hash functions
        for i in range(self.num_hash_funcs):
            location_hash = self.hash_funcs[i](self.location.encode('utf-8'))
            
        
            
        
            
        
        # Define a list of unique numerical values for each area
        area_values = [i+1 for i in range(10)] # example: 10 areas with values 1 to 10

        # Loop through the radius and set corresponding bits to the unique numerical values
        for i in range(int(radius * 100)):
            # Compute a hash for the current radius value
            radius_hash = hashlib.sha256(str(i).encode()).digest()

            # XOR the two hashes to get a bit index
            bit_index = int.from_bytes(location_hash, byteorder='big') ^ int.from_bytes(radius_hash, byteorder='big')

            # Modulo the bit index by the number of bits to get a valid index
            bit_index = bit_index % num_bits

            # Set the corresponding bit to the numerical value of the area
            bit_array[bit_index] = area_values[i % len(area_values)]

        # Convert the bit array to a byte string
        bit_string = ''.join(str(bit) for bit in bit_array)
        bloom_filter_bytes = int(bit_string, 2).to_bytes((num_bits + 7) // 8, byteorder='big')

        return bloom_filter_bytes

    # Example usage
    location = (40.7128, -74.0060) # New York City
    radius = 10 # 10km radius
    num_bits = 1024
    bloom_filter = generate_spatial_bloom_filter(location, radius, num_bits)
    

#example of conditional swap
def conditional_swap(swap_condition, a, b):
    # If swap_condition is True, swap a and b
    temp = a
    a = swap_condition * b + (1 - swap_condition) * a
    b = swap_condition * temp + (1 - swap_condition) * b
    return a, b

#Example of oblivious transfer protocol

def ot_1_out_of_2(sender_choice, receiver_choice1, receiver_choice2):
    # Generate random prime number p and generator g
    p = 23
    g = 5

    # Sender generates random private key a and public key A = g^a mod p
    a = random.randint(1, p-1)
    A = pow(g, a, p)

    # Receiver generates random private key b and public keys B1 = g^b mod p and B2 = g^(b+1) mod p
    b = random.randint(1, p-2)  # b has to be smaller than p-1 to avoid overflow
    B1 = pow(g, b, p)
    B2 = pow(g, b+1, p)

    # Sender sends the sender's choice to the receiver
    if sender_choice == 1:
        C1 = A * B1 % p
        C2 = A * B2 % p
    else:
        C1 = A * B2 % p
        C2 = A * B1 % p

    # Receiver sends receiver_choice1 to the sender
    k1 = pow(receiver_choice1, b, p)
    r1 = C1 ^ k1

    # Receiver sends receiver_choice2 to the sender
    k2 = pow(receiver_choice2, b+1, p)
    r2 = C2 ^ k2

    # Sender receives r1 and r2 and can compute the result based on the sender's choice
    if sender_choice == 1:
        result = r1
    else:
        result = r2

    return result

#example of convert wire into index
def convert_wire_to_index(wire):
    """
    Convert a wire to its corresponding index.

    Args:
        wire (list[int]): A list of 0s and 1s representing a wire.

    Returns:
        int: The index corresponding to the wire.
    """
    index = 0
    for bit in wire:
        index = (index << 1) | bit
    return index
