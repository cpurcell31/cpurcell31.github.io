import gmpy2
from Crypto.Util.number import long_to_bytes

class RSAModuli:
    def __init__(self):
        self.a = 0
        self.b = 0
        self.m = 0
        self.i = 0

    def gcd(self, num1, num2):
        """
        This function os used to find the GCD of 2 numbers.
        :param num1:
        :param num2:
        :return:
        """
        if num1 < num2:
            num1, num2 = num2, num1
        while num2 != 0:
            num1, num2 = num2, num1 % num2
        return num1

    def extended_euclidean(self, e1, e2):
        """
        The value a is the modular multiplicative inverse of e1 and e2.
        b is calculated from the eqn: (e1*a) + (e2*b) = gcd(e1, e2)
        :param e1: exponent 1
        :param e2: exponent 2
        """
        self.a = gmpy2.invert(e1, e2)
        self.b = (float(self.gcd(e1, e2) - (self.a * e1))) / float(e2)

    def modular_inverse(self, c1, c2, N):
        """
        i is the modular multiplicative inverse of c2 and N.
        i^-b is equal to c2^b. So if the value of b is -ve, we
        have to find out i and then do i^-b.
        Final plain text is given by m = (c1^a) * (i^-b) %N
        :param c1: cipher text 1
        :param c2: cipher text 2
        :param N: Modulus
        """
        i = gmpy2.invert(c2, N)
        mx = pow(c1, self.a, N)
        my = pow(i, int(-self.b), N)
        self.m = mx * my % N

    def print_value(self):
        print("Plain Text: ", long_to_bytes(self.m).decode())


def main():
    c = RSAModuli()
    N = 116668216162615410947228256134415238695563001587727998172087026549461099814632086269215663561469820240913771821761469222473492054567248769353452700092867265746579705202555313504962093090839255759461667273669729707056054447551547386490274403212468697316585303267080361571593191755392091986590854564288581691509
    c1 = 65389731423889696106594600664842112708140092620242386671437659692593174337020922608314807171715422000908198549825142251598535090987877908504098773252644260091557916760110879626278551211072474955441831711368558985330511469023363593322557798130411845413600212882610314991039988537639842016705932959141296268944
    c2 = 43233258697734681233140711542305298208379131813380320512450503226048017115236000171791884015079217532553788739474359214604155863466073064940303018952149941019611789580040836237199643893166817702092445793428926673641584432891088709958747505407433755690709850214438551800385000517578126446053043427647087796879
    e1 = 12357
    e2 = 65357
    c.extended_euclidean(e1, e2)
    c.modular_inverse(c1, c2, N)
    c.print_value()


if __name__ == '__main__':
    main()