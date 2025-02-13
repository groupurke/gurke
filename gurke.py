#%%
import random
import math
import hashlib
from sortedcontainers import SortedList
from cryptography.hazmat.primitives.asymmetric import x25519


def mod_print(*args):
    """
    Just printing for debugging
    """
    def mod_transform(val):
        if isinstance(val, int):
            return val % 100
        elif isinstance(val, list):  # Handle lists recursively
            return [mod_transform(item) for item in val]
        return val  # Return unchanged for other types

    new_args = [mod_transform(a) for a in args]
    print(*new_args)

class dhnike:
    # rfc3526 group 14
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    
    def __init__(self, g=None, p = None):
        if g:
            self.g = g
        if p:
            self.p = p

    def gen(self, seed=None):
        random.seed(seed)
        sk = random.randint(0, self.p)
        if seed:
            random.seed() #reset the seed so that future random calls arent predictable
        
        pk = pow(self.g, sk, self.p)

        return pk, sk

    def genpk(self, sk):
        pk = pow(self.g, sk, self.p)
        return pk
    
    def key(self, pk, sk):
        #TODO add hashing
        return pow(pk, sk, self.p)


class curve_nike:
    def gen(self, seed=None):
        if seed:
            # Hash the seed to get a 32-byte key
            hashed_seed = hashlib.sha256(seed).digest()

            # Create a private key from the hashed seed
            private_key = x25519.X25519PrivateKey.from_private_bytes(hashed_seed)
        else:
            private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return public_key, private_key
    
    def genpk(self, sk):
        return sk.public_key()
    
    def key(self, pk, sk):
        return sk.exchange(pk)
        

class ak:
    
    def __init__(self, nike):
        self.N = nike
    
    def gen(self):
        pk, sk = self.N.gen()
        return pk, sk
    
    def genpk(self, dk):
        pk = self.N.genpk(dk)
        return pk

    def prep(self, seed=None):
        """
            prepares for encapsulation 

            Returns:
                c : The ciphertext used for decapsulation
                r : The randomnessed used for finalization and key derivation
        """
        pk, sk = self.N.gen(seed)
        return pk, sk

    def enc(self, ek, r):
        pk = ek
        sk = r
        return self.N.key(pk, sk)
    
    def prep_enc(self, ek, seed=None):
        """
            does AK.prep and AK.enc in one step

            Returns:
                c : The ciphertext used for decapsulation
                k : The encapsulated key
        """
        c, r = self.prep(seed=seed)
        k = self.enc(ek, r)
        return c, k
    
    def dec(self, dk, c):
        sk = dk
        pk = c
        return self.N.key(pk, sk)


def H(*inputs):
    """Random oracle into  dk x k  spaces """
    def hash_512_bytes(*data):
        hasher = hashlib.sha512()
        for d in data:
            hasher.update(str(d).encode())

        hash_result = hasher.digest()
        
        # Repeat hashing or extend the hash output to make it 512 bytes
        extended_hash = b"".join(hashlib.sha512(hash_result + bytes([i])).digest() for i in range(8))
        return extended_hash

    res = hash_512_bytes(inputs)
    # match the group size of the nike (256 byte)
    dk, k = int.from_bytes(res[:256]), int.from_bytes(res[256:])
    return dk, k

def Hcurve(*inputs):
    """Random oracle into dk(curve) x k  spaces"""
    hasher = hashlib.sha256()
    hasher.update(str(inputs).encode())
    res = hasher.digest()
    res1, res2 = res[:32], res[32:]
    private_key = x25519.X25519PrivateKey.from_private_bytes(res1)

    return private_key, res2


# static path logic
def path(leaf:int):
        """leaf: index of the leaf"""
        path = []
        a = leaf + 1#self.leaves - 1
        while a != 1:
            path.append(a-1)
            a //= 2
        path.append(0)
        path.reverse()
        return path
    
def copath(leaf:int):
    """returns the copath of a leaf"""
    pat = path(leaf)
    copath = []
    for i in range(1, len(pat)):
        p = pat[i]
        cop = p+1 if (p%2 != 0) else p-1
        copath.append(cop)
    return copath

def parent(node:int):
    """returns parent index of a node"""
    return ((node+1)//2)-1

def leftchild(node:int):
    """returns index of the left child of a node"""
    return (node+1)*2-1

def rightchild(node:int):
    """returns index of the right child of a node"""
    return (node+1)*2

def sibling(node:int):
    """returns sibling index of a node"""
    if node%2 == 1:
        return node+1
    else:
        return node-1

def depth(node:int):
    """Computes the depth of a given node"""
    return (node+1).bit_length()-1

def new_leaf(leaf, deletion_depth):
    """
    Computes the new leaf index of a branch after one of its nodes got deleted (at deletion depth)
    """
    e = depth(leaf) - deletion_depth
    gs = pow(2, e-1)
    gn = (leaf+1)%gs
    pg = (pl := parent(leaf)+1) - (pl%gs)
    nleaf = pg+gn-1
    return nleaf

def move(tree, target:int, home:int):
    """
    Move node "home" to node "target" (with all children) in a listbased tree structure
    """
    at = target
    ah = home
    stack1 = list()
    stack2 = list()

    # depth first search
    while True:

        while ah < len(tree) and tree[ah]:
            stack1 += [ah]
            stack2 += [at]

            tree[at] = tree[ah]
            tree[ah] = None
            #compute left child
            ah = 2*ah + 1
            at = 2*at + 1
        
        # backtrack, select a right child instead of a left one
        while True:
            if len(stack1) == 0:
                break
            p = stack1.pop()
            t = stack2.pop()
            if p % 2 == 1:
                break
        
        if p == home:
            break
        ah = p+1
        at = t+1

class pathable:
    def path(self, leaf:int):
        return path(leaf)
    
    def _copath_(self, leaf:int):
        return copath(leaf)

class tree_ek(pathable):
    """A ubkem encapsulation key"""

    def __init__(self, intialdepth=3):
        self._depth = intialdepth
        self._data:list = [None] * self.size
    
    def __getitem__(self, index):
        return self._data[index]  # Allow indexing

    def __setitem__(self, index, value):
        if index >= self.size:
            # make the list bigger
            new_depth = int(math.log2(index+1))+1
            self._data.extend([None] * (pow(2, new_depth) - pow(2, self.depth)))
            self._depth = new_depth
        self._data[index] = value  # Allow item assignment
    
    def __len__(self):
        return len(self._data) 
    
    @property
    def depth(self):
        return self._depth
    
    @property
    def size(self):
        """Total number of nodes in the tree (empty nodes included)"""
        return pow(2, self.depth)-1

    

class tree_dk(pathable):
    """A ubkem decapsulation key"""

    def __init__(self, intialdepth=3, dk_list=None, leaf=None):
        #self._depth = intialdepth
        if dk_list:
            self._data = dk_list
        else:
            self._data:list = [None] * intialdepth
        self.leaf = leaf
    
    def pop(self, index):
        return self._data.pop(index)

    def __getitem__(self, index):
        return self._data[index]  # Allow indexing

    def __setitem__(self, index, value):
        self._data[index] = value  # Allow item assignment

    def __len__(self):
        return len(self._data)  # Return length

    def append(self, item):
        self._data.append(item)
    
    def path(self):
        """Returns the path indices of **this** decapsulation key"""
        return pathable.path(self, self.leaf)
    
    

class Tree:
    def __init__(self):
        pass
    
    @staticmethod
    def init(n):
        t = Tree()
        t.num_leaves = n
        t.size = 2*n-1
        return t
    
    def get_size(self):
        return self.size
    



    def nodes(self):
        """Outputs the list of indexes of all nodes in the tree."""
        return list(range(1, 2*self.n))

    def getnodes(self, ek):
        """Outputs the tree structure and public encapsulation keys."""
        return (self.tree_structure, self.public_keys)

    def setnodes(self, ek_list):
        """Packs the list of public encapsulation keys into the tree description."""
        ek = tree_ek()
        for i in range(len(ek_list)):
            ek[i] = ek_list[i]
        return ek
    
    @staticmethod
    def set_path(leaf, dks):
        """
        Returns a path of decapsulation nodes leading to the given leaf

            Args:
                leaf: index of a leaf in the tree
                dks: a list of keys, the list is interpreted to be a tree

            Returns:
                dk (tree_dk): A tree_dk object with the correct decapsulation keys and the correct leaf information
        """
        path_indices = path(leaf)
        dk_branch = [dks[i] for i in path_indices]
        return tree_dk(dk_list=dk_branch, leaf=leaf)


    
    @staticmethod
    def rm_ek(ek:tree_ek, i):
        """
            Computes path and copath of a leaf

            Args:
                ek (encapsulation key): a ubkem encapsulation tree
                i (int): index of the receiver to be removed

            Returns:
                p (list of indices): The enc_keys on the path of the removed leaf
                cp (list of indices): The enc_keys on the copath of a leaf
        """
        return ek.path(i), ek._copath_(i)
    
    @staticmethod
    def _intersection_depth(node1, node2):
        """
        returns the intersection depth of to tree nodes (usually l^star in the paper)
        """
        path1 = path(node1)
        path2 = path(node2)
        i = 0
        for a, b in zip(path1, path2):
            if a == b:
                i=i+1
            else:
                break
        l_star = i-1
        return l_star


    @staticmethod
    def rm_dk(dk:tree_dk, iprime):
        """
            Computes path and copath of a leaf

            Args:
                dk (decapsulation key): a ubkem decapsulation key
                iprime (int): index of the receiver to be removed

            Returns:
                l_star: depth of the node that is the intersection of the input receiver path and the receiver to be removed
        """
        path1 = dk.path()
        path2 = path(iprime)
        i = 0
        while path1[i] == path2[i]:
            i += 1
        l_star = i-1
        return l_star

    @staticmethod
    def add(ek):
        """
            Computes path and copath of a new node. Also number of the new leaf
        """
        lvs:SortedList = ek.leaves

        # get the smallest leaf, this leaf should be splitted
        first = lvs.pop(0)
        lchild, rchild = leftchild(first), rightchild(first)
        # add new leaves
        lvs.add(lchild)
        lvs.add(rchild)

        # let the encapsulation key go down
        ek[rchild] = ek[first]

        return path(lchild), copath(lchild), lchild
    
    @staticmethod
    def add_dk(dk:tree_dk, i):
        """
            Computes leaf pf input dk and intersection depth of dk with leaf i
        """
        return dk.leaf, dk, Tree._intersection_depth(dk.leaf, i)
        



    
class BK:

    def __init__(self, tree_structure, H1, H2, agnostic):
        """
        H1: Hash function into dk x k
        H2: Hash function into dk x s
        """
        self.T:type[Tree] = tree_structure
        self.H1 = H1
        self.H2 = H2
        self.AK:ak = agnostic
    
    @staticmethod
    def standard():
        """
        constructor for a standard configuration
        """
        nk = curve_nike()
        agnostic = ak(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=Hcurve, H2=Hcurve, agnostic=agnostic)
        return bk

    def gen(self, n):
        """
        sets up a BK instance with one sender and n receivers
        #TODO for now let's say n is a power of 2
        """
        t = self.T.init(n)

        s = t.get_size()

        depth = int(math.log2(n))+1
        eks = tree_ek(depth)
        dks = [None] * eks.size

        for j in range(s):
            eks[j], dks[j] = self.AK.gen()
        
        ek = eks

        dkis = [None] * n
        leafs = SortedList([i+n-1 for i in range(n)])
        
        for i in range(n):
            dkis[i] = self.T.set_path(leaf=i+n-1, dks=dks)
        
        ek.leaves = leafs
        
        return ek, dkis

    def enc(self, ek):
        """
        Encapsulates with an encapsulation key

            Args:
                ek (encapsulation key): a ubkem encapsulation key

            Returns:
                u: update data used in BK.fin to update the encapsulation key
                c: the ciphertext of the encapsulated key
        """
        cprime, r = self.AK.prep()

        c = ('E', cprime)

        u = (ek, r, c)
        return u, c
    
    def fin(self, u, ad):
        ek, r, c = u
        eks = ek
        
        N = len(ek)
        dks = [None] * N
        ks = [None] * N
        for j in range(N):
            if not ek[j]:
                continue
            kprime = self.AK.enc(eks[j], r)
            dks[j], ks[j] = self.H1(kprime, c, ad)
            eks[j] = self.AK.genpk(dks[j])
        k = ks[0]
        return eks, k

    def dec(self, dk, ad, c):
        t, cprime = c

        L = len(dk)
        ks = [None] * L
        dks = [None] * L
        for l in range(len(dk)):
            kprime = self.AK.dec(dk[l], cprime)
            dks[l], ks[l] = self.H1(kprime, c, ad)

            dks[l] = dks[l]
        k = ks[0]
        return tree_dk(dk_list=dks, leaf=dk.leaf), k

    def rm(self, ek, i):
        #TODO this function needs to update the leaves attribute of ek
        """
            Removes a receiver

            Args:
                ek (encapsulation key): a ubkem encapsulation tree
                i (int): index of the receiver to be removed

            Returns:
                ek (encapsulation key): The updated encapsulation key
                c: A ciphertext to be processed by all receivers to update their decapsulation key
        """
        path, copath = self.T.rm_ek(ek, i)
        cplen = len(copath)
        ek_star = [ek[i] for i in copath] #if ek[i] is not None]  <- actually because we have the invariant that every node has either none or two children this part is not needed: The copath always exists

        cl = dict()

        c_star, r = self.AK.prep()
        cl[depth(copath[-1])-1] = c_star
        k = self.AK.enc(ek_star[-1], r)

        dk_pl, s = self.H2(k, c_star)

        ek_pl = [None] * cplen
        ek_pl[-1] = self.AK.genpk(dk_pl)

        for l in range(cplen-2, -1, -1): 
            # cl[l], k = self.AK.enc(ek_star[l], s) <- is written in the paper but the normal AK.enc cant be ment because it returns only the key, not a ciphertext
            # So probably a deterministic version of prep & enc is ment
            cl[depth(copath[l])-1], _r = self.AK.prep(s)
            k = self.AK.enc(ek_star[l], _r)
            dk_pl, s = self.H2(k, c_star)

            ek_pl[l] = self.AK.genpk(dk_pl)
        
        # update the public key, T.setpath in the pseudocode
        for a in range(len(copath)):
            ek[path[a]] = ek_pl[a]
        # delete old leaf
        ek[path[-1]] = None

        # now move the tree so that invariant holds, delete the brother of deleted node
        # TODO also maybe consider doing a pointer based tree and code everything (like most stuff) from scratch because of this

        move(ek, parent(i), sibling(i))


        
        c = ('R', (i, ek_star, cl))

        return ek, c
    
    def add(self, ek):
        p, cp, n =self.T.add(ek)
        ek_star = [ek[i] for i in cp]

        ekpl, dkpl = self.AK.gen()
        #s = int.from_bytes(random.randbytes(8)), instead of this we just use the random version of prep_enc 
        s = None

        cl = [None] * ((L:=len(p))-1)
        dk = [None] * (L-1)
        for l in range(L-1, 0, -1):
            cl[l-1], k = self.AK.prep_enc(ek=ek[cp[l-1]], seed=s)
            dk[l-1], s = self.H2(k, cl[l-1])
            ek[p[l-1]] = self.AK.genpk(dk[l-1])

        dk = tree_dk(dk_list=dk, leaf=n)
        c = ('A', (ek_star, cl, n)) #TODO for now add n to the ciphertext, shouldn't change security in any way as this value could also just be guessed by an attacker

        return ek, dk , c

    
    def proc(self, dk:tree_dk, c):
        """
        Processes a ciphertext that changes the group members
        This can be either of these:
        1. A fork of the public key, meaning a sender was added and the decapsulation key has t be split into 2 aswell
        2. Adding a new receiver
        3. Removing a receiver, which means secrets of the given decapsulation key that match with the removed one need to be renewed
        """

        t, cprime = c
        if t == "F":
            siz = len(dk)
            new_dk1 = [None] * siz
            new_dk2 = [None] * siz
            for l in range(siz):
                k = self.AK.dec(dk[l], cprime)
                #mod_print('proc k: ', k)
                new_dk1[l], _k = self.H1(k,c,'1')
                new_dk2[l], _k = self.H1(k,c,'2')
            
            new_dk1 = tree_dk(dk_list=new_dk1, leaf=dk.leaf)
            new_dk2 = tree_dk(dk_list=new_dk2, leaf=dk.leaf)

            #mod_print(new_dk2._data)

            return new_dk1, new_dk2

        if t == "A":
            ekl, cl, n = cprime
            i, dk, l_star = self.T.add_dk(dk, n)
            if l_star == len(dk)-1:
                dk.append(dk[-1])
        if t == "R":
            iprime, ekl, cl = cprime
            l_star = self.T.rm_dk(dk, iprime)
        dk_circle = dk[l_star+1]
        c_circle = cl[l_star]

        dkl = [None] * (l_star + 1)
        k = self.AK.dec(dk_circle, c_circle)
        dkl[l_star], s = self.H2(k, c_circle)

        # check if this dk has the node that needs to be deleted
        if l_star+1 == len(cl):
            dk.pop(l_star+1)

            # find the correct new  leaf index
            dk.leaf = new_leaf(dk.leaf, l_star)
            


        for l in range(l_star-1, -1, -1):
            c_circle, k = self.AK.prep_enc(ekl[l], s)
            dkl[l], s = self.H2(k, c_circle)
        
        # update the decapsulation key #TODO maybe do this out of place
        dk[0:(l_star+1)] = dkl
        return dk





    

    def fork(self, ek:tree_ek):
        """
            Forks the encapsulation key, adding a new sender.

            Args:
                ek (encapsulation key): a ubkem encapsulation tree

            Returns:
                ek1 (encapsulation key): A new encapsulation key
                ek2 (encapsulation key): A new encapsulation key
        """

        cprime, r = self.AK.prep()
        c = ('F', cprime)

        eks1 = tree_ek(ek.depth)
        eks2 = tree_ek(ek.depth)

        for j in range(len(ek)):
            if not ek[j]:
                continue
            k = self.AK.enc(ek[j], r)
            #mod_print('fork k: ', k)
            dk2, _k2 = self.H1(k,c,'2')
            dk1, _k1 = self.H1(k,c,'1')
            #dk2, _k2 = self.H1(k,c,'2')
            #mod_print(dk2)
            eks1[j] = self.AK.genpk(dk1)
            eks2[j] = self.AK.genpk(dk2)
        
        return (eks1, eks2, c)




