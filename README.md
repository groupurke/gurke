This is a proof of concept implementation of the **Dynamic Updatble Broadcast KEM**, which is used in the dynamic constructions of **Group Unidirectional Ratcheted Key Exchange (GURKE)**.
The performance of this implementation was benchmarked for groups with **2^m members, where 0<m<11**.
Algorithms fin, dec, and fork where **executed 200 times** and the median running time was taken as the result.
The code was executed on a machine with a 13th Gen Intel(R) Core(TM) i5-13 processor.
For Non-Interactive Key Exchange, we use Diffie-Hellman with Curve25519.
