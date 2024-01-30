def round_div(a, b):
    q = a // b
    r = a % b

    return q if (r <= (b // 2)) else q + 1


def ee(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = (r, (old_r - quotient * r))
        old_s, s = (s, (old_s - quotient * s))
        old_t, t = (t, (old_t - quotient * t))

        print(old_r == ((old_s * a) % b))

        print("---------------")
        print(old_r)
        print(old_s)
        print(old_t)
        print(r)
        print(s)
        print(t)

v1 = [147946756881789319020627676272574806254, -147946756881789318990833708069417712965]
v2 = [147946756881789319000765030803803410728, 147946756881789319010696353538189108491]
n = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
lambda_1 = 0xb3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd
# lambda_2 = 0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48

ee(lambda_1, n)
# ee(lambda_2, n)

assert (v1[0] + lambda_1 * v1[1]) % n == 0
assert (v2[0] + lambda_1 * v2[1]) % n == 0

x1, y1, x2, y2 = v1[0], v1[1], v2[0], v2[1]
determinant = x1 * y2 - x2 * y1


def decompose(k):
    a1 = y2 * k
    a2 = -y1 * k

    z1 = round_div(a1, determinant)
    z2 = round_div(a2, determinant)

    k1 = k - (z1 * x1 + z2 * x2)
    k2 = -(z1 * y1 + z2 * y2)

    return k1 % n, k2 % n


def test_decompose(k):
    k1, k2 = decompose(k)
    print (hex(k1), hex(k2))
    assert k == (k1 + (k2 * lambda_1)) % n


# test_decompose(7)
test_decompose((n + 1) // 2)
# test_decompose(n - 127)
# test_decompose(n - 2)
# test_decompose(n // 2)
# test_decompose(lambda_1)

