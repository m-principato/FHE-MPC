# FHE-MPC
This implements a secure Multi-party Computation (MPC) via threshold Fully Homomorphic Encryption.

Up until now it is implemented via the rakerski/Fan-Vercauteren scheme (BFV)) scheme. More precisely its distributed version (dBFV) provided by the LattiGo Library.
It only supports integers and output values up to the crypto setup modulus of 65537.
