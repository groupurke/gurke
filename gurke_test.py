import unittest

from gurke import dhnike as nike
from gurke import Tree, BK, H, mod_print

class TestNike(unittest.TestCase):

    def test_correctness(self):
        nik = nike()

        pk1, sk1 = nik.gen()
        pk2, sk2 = nik.gen()
        k1 = nik.key(pk1, sk2)
        k2 = nik.key(pk2, sk1)
        self.assertEqual(k1, k2)


from gurke import ak as akem

class TestAkem(unittest.TestCase):

    def test_correctness(self):
        ak = akem(nike())
        ek, dk = ak.gen()
        self.assertTrue(check_ak_keypair(ek, dk, ak))


def check_ak_keypair(ek, dk, ak=None):
    """
            Checks that an ak keypair is compatible

            Args:
                ek (encapsulation key): a ak encapsulation tree
                dk (decapsulation key): a dk decapsulation tree

            Returns:
                true if compatible
        """
    if not ak:
        ak = akem(nike())
    c, r = ak.prep()
    k1 = ak.enc(ek, r)
    k2 = ak.dec(dk, c)
    return k1 == k2

def check_keys(ek, dks:list, ak=None):
    """
            Makes sure that the ubkem encapsulation key is compatible with the given list of ubkem decapsulation keys

            Args:
                ek (encapsulation key): a ubkem encapsulation tree
                dk (decapsulation key): a ubkem decapsulation tree

            Returns:
                true if compatible
        """
    # Find all paths in the ek through depth-first search
    stack = list()
    a = 0

    compatible = True

    while True:

        while a < len(ek) and ek[a]:
            stack += [a]
            #compute left child
            a = 2*a + 1
        leaf = (a - 1)//2

        #find the right dk
        for dk in dks:
            if dk.leaf != leaf:
                continue
            for i in range(len(stack)):
                compatible &= check_ak_keypair(ek[stack[i]], dk[i], ak=ak)
        
        # backtrack, select a right child instead of a left one
        while True:
            if len(stack) == 0:
                break
            p = stack.pop()
            if p % 2 == 1:
                break
        
        if p == 0:
            break
        a = p+1
    
    return compatible

class TestMisc(unittest.TestCase):

    pass

class TestBK(unittest.TestCase):

    def test_gen(self):
        nk = nike()
        agnostic = akem(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=H, H2=H, agnostic=agnostic)
        ek, dks = bk.gen(4)

        self.assertTrue(check_keys(ek, dks))

    def test_fork(self):
        nk = nike()
        agnostic = akem(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=H, H2=H, agnostic=agnostic)
        ek, dks = bk.gen(4)

        ek1, ek2, c = bk.fork(ek)

        dks1, dks2 = [None] * len(dks), [None] * len(dks)
        for i in range(len(dks)):
            dks1[i], dks2[i] = bk.proc(dks[i], c)
        
        self.assertTrue(check_keys(ek1, dks1))
        self.assertTrue(check_keys(ek2, dks2))

        self.assertFalse(check_keys(ek1, dks2))
        self.assertFalse(check_keys(ek2, dks1))
            



    def test_two_encaps(self):
        nk = nike()
        agnostic = akem(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=H, H2=H, agnostic=agnostic)
        ek, dks = bk.gen(4)

        self.assertTrue(check_keys(ek, dks))
        u, c = bk.enc(ek)
        ad = 'ad'
        ek_new, k = bk.fin(u, ad)
       # print('k_ek:',hex(k))

        dks_new = list()
        for dk in dks:
            dk_new, k = bk.dec(dk, ad, c)
            dks_new.append(dk_new)
           # print('k_dk',hex(k))
        self.assertTrue(check_keys(ek_new, dks_new))

        ek = ek_new
        dks = dks_new
        u, c = bk.enc(ek)
        ek_new, k = bk.fin(u, ad)
       # print('k_ek:',hex(k))

        dks_new = list()
        for dk in dks:
            dk_new, k = bk.dec(dk, ad, c)
            dks_new.append(dk_new)
           # print('k_dk',hex(k))
        self.assertTrue(check_keys(ek_new, dks_new))
    

    def test_rmv(self):
        nk = nike()
        agnostic = akem(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=H, H2=H, agnostic=agnostic)
        ek, dks = bk.gen(4)

        ek, c = bk.rm(ek, 3)

        # delete the removed dk
        dks.pop(0)

        for i in range(len(dks)):
            dks[i] = bk.proc(dks[i], c)

        self.assertEqual(dks[0].leaf, 1)
        self.assertEqual(dks[1].leaf, 5)
        self.assertEqual(dks[2].leaf, 6)
        #mod_print(ek._data)
        for dk in dks:
            pass
            #mod_print(dk._data)
    
    def test_add(self):
        nk = nike()
        agnostic = akem(nk)
        tree = Tree()

        bk = BK(tree_structure=tree, H1=H, H2=H, agnostic=agnostic)
        ek, dks = bk.gen(4)

        ek, dk, c = bk.add(ek)

        dk[0] = bk.proc(dks[0], c)

if __name__ == '__main__':
    #unittest.main()
    #unittest.main(defaultTest=['TestBK.test_two_encaps'])
    #unittest.main(defaultTest=['TestBK.test_gen'])
    #unittest.main(defaultTest=['TestBK.test_rmv'])
    unittest.main(defaultTest=['TestBK.test_add'])