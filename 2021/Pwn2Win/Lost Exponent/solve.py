from random import seed, shuffle
from itertools import product
from math import sqrt, log
from numpy import sign, diff
from string import punctuation, digits, ascii_letters


charset = punctuation + digits + ascii_letters
ncs = list(map(ord, charset))
cs_lims = (min(ncs), max(ncs))


class Matrix:
    def __init__(self, n):
        self.n = n
        self.m = [[0] * n for _ in range(n)]
        self.pd = dict()

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix(self.n)
        for i in range(self.n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value
        del self.pd
        self.pd = dict()

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix(self.n)
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k] * other[k, j] for k in range(n))
        return r

    def __pow__(self, n, modulo=None):
        if n == 0:
            return self.I()
        if n == 1:
            return self
        if n not in self.pd:
            n2 = self ** (n >> 1)
            self.pd[n] = n2 * n2
            if n & 1:
                self.pd[n] = self.pd[n] * self
        return self.pd[n]

    def __str__(self):
        return str(self.m)


if __name__ == '__main__':
    with open('enc', 'rb') as inflag:
        cf = inflag.read()
    nc = len(cf)
    nf = len('CTF-BR{}')+1
    while True:
        print(f'Trying nf = {nf}...')
        n = int(sqrt(nf)) + 2
        n2 = n ** 2
        if nc % n2 != 0:
            nf += 1
            continue
        nb = nc // n2

        cflag = [int(''.join([str(c).zfill(2) for c in cf[i:i + nb]]))
                 for i in range(0, len(cf), nb)]

        if len(cflag) != n2:
            nf += 1
            continue

        mflag = Matrix(n)
        for i in range(n):
            for j in range(n):
                mflag[i, j] = cflag[i * n + j]

        seed(6174)
        n = int(sqrt(nf)) + 2
        order = list(product(range(n), repeat=2))
        shuffle(order)
        order.sort(key=(lambda x: sign(diff(x))))

        pos00 = order.index((0, 0))
        mf00 = mflag[0, 0]
        M = (float('inf'), '', 0)
        for c in charset:
            lg = int(log(mf00, ord(c)))
            M = min(M, (abs(ord(c) ** lg / mf00 - 1), c, lg))
            if M[0] == 0:
                break
        e = M[2]
        flag = 'CTF-BR{' + (nf - 8) * ' ' + '}'
        flag = flag[:pos00] + M[1] + flag[pos00 + 1:]
        print(flag)

        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)

        if (m ** e)[0, 0] != mflag[0, 0]:
            nf += 1
            continue

        for d in range(n):
            for k in range(n-d):
                mp = (k + d, k)
                if mp == (0, 0):
                    continue
                posmp = order.index(mp)
                if posmp < len('CTF-BR{'):
                    continue
                mfmp = mflag[mp]
                if mfmp == 0:
                    continue
                M = (float('inf'), 0)
                beg, end = cs_lims
                m[mp] = beg
                beg = (beg, sign((m ** e)[mp] - mfmp))
                m[mp] = end
                end = (end, sign((m ** e)[mp] - mfmp))
                while True:
                    c = (beg[0] + end[0]) // 2
                    m[mp] = c
                    c = (c, sign((m ** e)[mp] - mfmp))
                    if c[1] == 0:
                        M = c[::-1]
                        break
                    if c[1] == beg[1]:
                        beg = c
                    elif c[1] == end[1]:
                        end = c
                    else:
                        raise Exception('How I am here????')
                m[mp] = M[1]
                flag = flag[:posmp] + chr(M[1]) + flag[posmp + 1:]
                print(flag)
                if flag[nf-1] != '}':
                    break
            if flag[nf-1] != '}':
                break
        if flag[nf-1] != '}':
            nf += 1
            continue

        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)

        if sum(int(a == b) for a, b in zip((m ** e), mflag)) == mflag.n ** 2:
            break

        nf += 1

    print(flag)
