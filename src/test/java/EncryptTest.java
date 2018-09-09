import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Test suite for the Encrypt class.
 * <p>
 * The provided test suite is correct and complete. You should not need to modify it. However, you
 * should understand it. You will need to augment or write test suites for later MPs.
 *
 * @see <a href="https://cs125.cs.illinois.edu/MP/1/">MP1 Documentation</a>
 */
public class EncryptTest {

    /** Timeout for simple tests. */
    private static final int SIMPLE_TEST_TIMEOUT = 100;

    @Test(timeOut = SIMPLE_TEST_TIMEOUT)
    public void testEncryptWithGoodInputs() {
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.encrypter("CS125".toCharArray(), 0))),
                "CS125");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.encrypter("CS125".toCharArray(), 1))),
                "DT236");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.encrypter("DT236".toCharArray(), -1))),
                "CS125");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.encrypter("CS125".toCharArray(), 95))),
                "CS125");
    }

    @Test(timeOut = SIMPLE_TEST_TIMEOUT)
    public void testDecryptWithGoodInputs() {
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.decrypter("GWA".toCharArray(), 0))),
                "GWA");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.decrypter("GWA".toCharArray(), 1))),
                "FV@");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.decrypter("CS".toCharArray(), -1))),
                "DT");
        Assert.assertEquals(new String(Objects.requireNonNull(Encrypt.decrypter("CS".toCharArray(), 96))),
                "BR");
    }

    @Test(timeOut = SIMPLE_TEST_TIMEOUT)
    public void testBadInputs() {
        Assert.assertNull(Encrypt.encrypter("Bad".toCharArray(), 1025));
        Assert.assertNull(Encrypt.encrypter("Bad".toCharArray(), -1025));
        Assert.assertNull(Encrypt.decrypter("Bad".toCharArray(), 1025));
        Assert.assertNull(Encrypt.decrypter("Bad".toCharArray(), -1025));
    }

    /** Timeout for grading test. Solution takes 29 ms. */
    private static final int GRADING_TEST_TIMEOUT = 600;

    private static final Map<EncryptInput, String> PRECOMPUTED_RESULTS = //
            new LinkedHashMap<>();

    /**
     * Test encryption and decryption.
     */
    @Test(timeOut = GRADING_TEST_TIMEOUT)
    public void gradeEncrypt() {


        for (Map.Entry<EncryptInput, String> precomputedResult : PRECOMPUTED_RESULTS.entrySet()) {

            EncryptInput input = precomputedResult.getKey();
            String precomputedOutput = precomputedResult.getValue();
            if (precomputedOutput != null) {
                precomputedOutput = URLDecoder.decode(precomputedOutput, StandardCharsets.UTF_8);
            }

            char[] line = URLDecoder.decode(input.line, StandardCharsets.UTF_8).toCharArray();

            char[] expectedOutput = null;
            if (precomputedOutput != null) {
                expectedOutput = precomputedOutput.toCharArray();
                Assert.assertEquals(line.length, precomputedOutput.length());
            }
            char[] copyOfLine = line.clone();
            char[] transformedLine;
            if (input.encrypt) {
                transformedLine = Encrypt.encrypter(line, input.shift);
            } else {
                transformedLine = Encrypt.decrypter(line, input.shift);
            }
            if (transformedLine != null) {
                Assert.assertEquals(transformedLine.length, copyOfLine.length);
            }
            /*
             * Ensure that encrypter and decrypter do not modify the original array
             */
            Assert.assertNotSame(transformedLine, line);
            Assert.assertEquals(String.valueOf(line), String.valueOf(copyOfLine));

            /*
             * Check expected output
             */
            if (expectedOutput != null) {
                Assert.assertNotNull(transformedLine);
                Assert.assertEquals(String.valueOf(transformedLine), String.valueOf(expectedOutput));
            } else {
                Assert.assertNull(transformedLine);
            }
            /*
             * Stopping point for invalid values
             */
            if (expectedOutput == null) {
                continue;
            }
            Assert.assertEquals(String.valueOf(transformedLine), String.valueOf(expectedOutput));

            /*
             * Now undo the transformation
             */
            char[] copyOfTransformedLine = transformedLine.clone();
            char[] reformedLine;
            if (input.encrypt) {
                reformedLine = Encrypt.decrypter(transformedLine, input.shift);
            } else {
                reformedLine = Encrypt.encrypter(transformedLine, input.shift);
            }

            /*
             * Ensure that encrypter and decrypter do not modify the original array
             */
            Assert.assertNotSame(line, reformedLine);
            Assert.assertEquals(String.valueOf(line), String.valueOf(copyOfLine));
            Assert.assertNotSame(transformedLine, reformedLine);
            Assert.assertEquals(String.valueOf(transformedLine), String.valueOf(copyOfTransformedLine));

            /*
             * Check expected output. We should be back to the original string.
             */
            Assert.assertNotNull(reformedLine);
            Assert.assertEquals(String.valueOf(reformedLine), String.valueOf(line));
        }
    }

    public static class EncryptInput {

        /** Line to encrypt or decrypt. */
        final String line;

        /** Whether to encrypt or decrypt. */
        final boolean encrypt;

        /** Encryption or decryption shift. */
        final int shift;

        EncryptInput(String line, boolean encrypt, int shift) {
            this.line = line;
            this.encrypt = encrypt;
            this.shift = shift;
        }
    }

    /** Initialization routine. */
    public EncryptTest() {
        EncryptTest.PRECOMPUTED_RESULTS
                .put(new EncryptInput("", true, 8), "");
        EncryptTest.PRECOMPUTED_RESULTS
                .put(new EncryptInput("a", true, 1), "b");
        EncryptTest.PRECOMPUTED_RESULTS
                .put(new EncryptInput("b", true, -1), "a");
        EncryptTest.PRECOMPUTED_RESULTS
                .put(new EncryptInput("b", false, 1), "a");
        EncryptTest.PRECOMPUTED_RESULTS
                .put(new EncryptInput("a", false, -1), "b");
        /* BEGIN AUTOGENERATED CODE */
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("abc", true, 1), "bcd");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("bcd", false, 1), "abc");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("n__hJ%2C5%2C8-x%7CVXxuJ!tm6%26uK1I%3A%5C.06DO%5BmtD%20)E%5DW%26%7B(c%22i*XCt%7D60im!u%40%3E%26t(%60qPATGv9nWR", true, -838), "%20ppy%5B%3DF%3DI%3E*.gi*'%5B2%26~G7'%5CBZKm%3FAGU%60l~%26U1%3AVnh7-9t3z%3BiT%26%2FGAz~2'QO7%269q%23aReX(J%20hc");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("wq%5B(bEcCy7%26%3AYF%3B%3F%60%405'6dAD%22s%7BhKPm9uEuFhqQ%2Br%7D%40%26%7Ca%20-HHo3%7CP~N6%3BfBPNd)O-O__6(L!f0CgYFfgE%26%40DBkPuxh69'YUP%5E%3E5G%2BC%3Bx%7Bb%5Cr%7Cd%2FD'4quG%60c%23iBK%40", false, 1024), "-'p%3DwZxX%2FL%3BOn%5BPTuUJ%3CKyVY7)1%7D%60e%23N%2BZ%2B%5B%7D'f%40(3U%3B2v5B%5D%5D%25H2e4cKP%7BWecy%3EdBdttK%3Da6%7BEX%7Cn%5B%7B%7CZ%3BUYW!e%2B.%7DKN%3CnjesSJ%5C%40XP.1wq(2yDY%3CI'%2B%5Cux8~W%60U");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-'%3DvJZwbOv1'R1Ig3E6%3BNuZO%3A%3Fo~%7Dsr%5Dv9%7D_2%3BYA(5~DyK", true, -1295), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%22%26Wy*%264G%5D%5Dz%7B%3A(Qz%3AXyMO7fY%3EQth3Ez%24JplYQ9f%5B%2FRp%20kT%2CcO%3DS%40(%5D5'ZUb%23m%7B98AHj%2401Qir.%2F9n7%22D*b(x)ZS%2F%3E%7DdK7D*C_G%3BM%2F%7B%3B(", false, -428), "RV(JZVdw..KLjX%22Kj)J%7D%20g7*n%22E9cuKTzA%3D*%22i7%2C_%23AP%3C%25%5C4%20m%24pX.eW%2B%263S%3ELihqx%3BT%60a%22%3AC%5E_i%3FgRtZ3XIY%2B%24_nN5%7BgtZs0wk%7D_LkX");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%26J.f%20p%7Dk%2B%60PP4Eug'S'%2FfsF!ztXzOF%3C%26EKq%2C%2Cp)j_o%3BM%3Dy-n1XWl%3EKimrp%3B0G*%22zo", true, -424), "Y%7Da%3ASDQ%3F%5E4%24%24gxI%3BZ'Zb%3AGyTNH%2CN%23yoYx~E__D%5C%3E3Cn!pM%60Bd%2C%2B%40q~%3DAFDncz%5DUNC");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("(%25ky%7BmT1ImgVrDJp%3BPol9%23%23iheNLmf%3E%5E%5B%3FzU2b%7Dm%3DaM%2Fn%7B%7CKfc%22NKbOk%5Dkstm2G5dEvSd(%60%5DGvr", true, -7184), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("qa%22%60%24)Dqf_wW8%20XCKh%3A1i8n%25_fFh%20pd%266*%3B)%25kKdDe!X%60kys%7B%3BXyb%7CUS%251Ag%7BDK1z%5Dx)d", true, 9038), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("PHlV%25)ZXRZ%40k!O(cAi%3B%3C(fN%3B%20KA%204HRz0TC%7BRPu0RBx%5DKo%5Bw%20%608", false, -3094), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("j~1KJ2p%24k%23mds6d%2C%3DHf%26phZC%3F3(YU%3DHMayrz5%7D_C-0.HiTl%26Y4NK'eH3t~m9wxPa%5Ekg%3Dn%23a%5C%3AH%3CD%3A(PcJCZ%3C~0('I8uldFXB%23b%3D%5B.", false, 3802), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Bt'Yls5uY3jh%40LpVQS'YgY.%2F19%2F_wfxeY%20aQ%5B%5D.!e%7B*P%60DVa%24e%2CO2v9F%5BR%25At%3FTi-4qo%40J1s%3FB*tZ.~%3D8z_%3A%3A", true, 125), "%603Ew%2B2S4wQ)'%5Ej%2FtoqEw%26wLMOWM%7D6%257%24w%3E%20oy%7BL%3F%24%3AHn~bt%20B%24JmP5WdypC_3%5Dr(KR0.%5EhO2%5D%60H3xL%3D%5BV9%7DXX");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("k75~9cs%3F%3A%2Be%3CT7F)fq9%40%5D%2Fxi8%5B%25h.q%3BxrN%3Dm%5EwJ03cA%20!'%3C%3D%3E%24%3Bq1v%2219M%5Cb%5ERrp%2C%2CAxAOZPr%24(6ZS%25%5CY!w9%5C%5Eo!%3Dx%22qym%60%5C%22%7B2_IExiczJIeD0W_%5C)~sE%3Fi36beG%22vk", true, -8570), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("bRJiK%25KoWf%40RkW-XtaZy%25%24_FehN%3C2%5C81C%3E%20.1%3AJnqYaVMg%3D)3%26N)%3Efy%5CKLx%5C*B6s(3%3B%2B%5EIMX_3YlTgy%3CvpZ*%7DyADrrd%3EqYf%7Dyv.yq76", false, -7005), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%208%3DDM'h1zCYI%3DVi%23CLy'dmj%25D%3FF%7C%3A4aR0%404%3E2%5BE8JI%2FCU%60L~'%22_%7CX%2BSOH%7BAd~3sHG%2CTv().oy(%5D%5B%5C1%40l%60J%2B0", false, 501), "e%7D%23*3lNv%60)%3F%2F%23%3COh)2_lJSPj*%25%2Cb%20yG8u%26y%24wA%2B%7D0%2Ft)%3BF2dlgEb%3Ep95.a'JdxY.-q%3A%5CmnsU_mCABv%26RF0pu");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%23-0NC%3C%3A%26Ek%7CL%25W%5DAmN8t_2%7B%2FRi%22HFx%7B_hFHo4%7B%22%60%3BgL!Zb%3C7bPcF5wo%40%3A-%3Fu%3BK%202'%20%3ArS%7DJiO%5E%5DK%2C%5CJ-g-%23Q%3F%22%2Fd8%60", false, 987), "%5Dgj)%7Dvt%60%20FW'_28%7BH)rO%3AlVi-D%5C%23!SV%3AC!%23JnV%5C%3BuB'%5B5%3Dvq%3D%2B%3E!oRJztgyPu%26ZlaZtM.X%25D*98%26f7%25gBg%5D%2Cy%5Ci%3Fr%3B");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%254F)mZNSa-E%24%3BhlR%3B%7CH%23_GZ)zc-Lz6%5Do*4%24Unj%60%3BMN5e.WC%2CfsQ8fU%5E0U6n%3BA0m!nXqt0''1wJ%2F%5Exck", true, -1831), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("NOQCKg%3B1vIc)cjkA%2Bl%5Ea!a%2C%2C-*w%2C%2C'72*Fg%26%7Bi-t%3EbInicHe%3AZ%24wMqK%3FoONa%5BD)%5Cv-jG%7CN%5E%3CZ%5D%2BI5%20%2B8", true, -1681), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%09zpJGG%C3%87%24%40R85%0DtpH%23%C3%87Y0de%2F%0A%C2%A93Fiw%C3%87Zf-%2CN%0A%0DWc%0D_.%3E", true, -162), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("9%C2%A9n%24c%C3%87H%3BC%5EQ%C3%91v%5C%24%2Cqu%24%20(%7C.974Nz%0D6%3ArfU)%0APl%3D%7Cs%5BwxU%40CoU%2Cc2%3EB%228l.%7DD%C2%A9GC", false, -245), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("0JixXuLQRahLi3%3AtWJY0i4hxeTt%7C%20%5D!0H%20-%5D%5Ce%5CA%3E4MDQ%5C~%3F)0%206%3Aj%24%3By%5D%25uyK1zK7L%5E-!1_uy4q%2CU%2C%605ii", true, -343), "Uo%2F%3E%7D%3Bqvw'.q%2FX_%3A%7Co~U%2FY.%3E%2By%3ABE%23FUmER%23%22%2B%22fcYriv%22DdNUE%5B_0I%60%3F%23J%3B%3FpV%40p%5Cq%24RFV%25%3B%3FY7QzQ%26Z%2F%2F");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("d%5E%22q464%7D%5B~%3A71eBCdL*~0%2FnbB1b6xFRu%5D%25%60", true, -4430), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Ed'%60mJLkjK7ytCqAIj*%60%5B~%3F%7C%5B%2B%7D%7DGsRqV3)U%5C%24MyxfWS0%25Rxyq%7D%26BAk8lQl3", false, -9), "Nm0ivSUtsT%40%23%7DLzJRs3id(H%26d4''P%7C%5Bz_%3C2%5Ee-V%23%22o%60%5C9.%5B%22%23z'%2FKJtAuZu%3C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("6tVvJ5QOi%3AN%3B0X%23x%5Di4f!cNieK%2BC%5E0CEziU%20Uy%3D.%2BYn%3CM'HvyxO.%2Ct%3Ar%26%5Bgv%3Fg%7B%2B.P%23%60ue5nz.5f5Rl0OjiOo%40%26%5EZBmmscZYIB%2Fdm8G6AlhJ*M'DNjT%2FH7CB%3F0sv%5E", true, -9861), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C3%91YE%7B%24%0Ap%5B_Rt.%7DjW5%7C)mgW%0D-p%C3%91OLDLn0rOcP%7B5%5D%09xtLCW%24JTDu%3EN2d%40q%C3%87b%23XL-Ix%2B(a%2BDOCl8%26%C3%87'%7D3-0k1X%23U%2BxyEm!_3%24%22J%60%26", false, -878), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("F0s-gQfRDw~%2CY%7Cj0%3D0K%2F%25waX1Ym8JT_a%3Db%22q%7CBq%2F", false, -666), "G1t.hRgSEx%20-Z%7Dk1%3E1L0%26xbY2Zn9KU%60b%3Ec%23r%7DCr0");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("5aomUM%26B%20e%260h'SdaV%5EgL%C2%A9%C3%91%3ELlEBO%3BOb5%C3%91%3Dpj%22%3BY_.1g%7C%5B'n0%C2%A9v%3E%5E%5D_F*c.3H%20OK_m-Vv1-t4MAQ%3C9-Y%C3%87Hy%3EDR2%5D*f%0D%3B%25lX%3Ek%60%7DuBNmk%09v%25%3CtTka%7Da)", true, 668), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Z%5BFuU%3FKS%3F%23D9wf%7DjF%3CjY1%23h%3E%5DjS%25%22ff'%2Ckw%5CRrlGshd%5C90I%60%60*rLp-4A'vCI.%245cqrDx-%20%2472d6%3A(~~Z_%3EiT%7CuR%20-%7D7vS%5Dx%2FyQb*m.%3D)fI%3C*%3C%5C", false, 9660), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("MIWO%3Cs%7DI~4UvNuPFk!QQ%2Cq3RSR!%3FrV%22Uoz%3D0ep%20e6d9'%2BMk(%5Epi%3D%5DLfVq%40w(t%22(~k%7B0DBgkGs%22p3%24%26eOX%60B%5BZ(%3E-%7C)m%24R%24%3C1%2Bc%3Cp2VLT", true, -3190), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2C%7BE%25%20cG%7DmyEG87%3F%7D%5C%5E%2Cq9%3B)wol7J%3BheYWrEGS6C%25%7BE8P%3Azzn%5DsjqT%3Fy%23VSGQ%5Bm%2B1dx!%5Bu)ZgbTY%26Zyse(rp%3AK%2BWox4%409%2Cf8~UID'L", true, -366), "%3A*S3.qU%2C%7B(SUFEM%2Cjl%3A%20GI7%26%7DzEXIvsge!SUaDQ3*SF%5EH))%7Ck%22x%20bM(1daU_i%7B9%3Fr'%2Fi%247hupbg4h(%22s6!~HY9e%7D'BNG%3AtF-cWR5Z");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("L%09%3BE%7C5uY%60%25Z8*u%2Bs*%24Qddu6L%7B%C3%87%C2%A9E%7BKCuGrUVht%5DW%5E%0DG%5B%0Ay%2BU%0Ad0%5D0h!%60v%C3%87ooV%C3%91%3A%09CI-r%40%C3%91yl.o_4%5CC%3E6%5B%C3%87%C3%87%3E%3F%5Ec'%7CZVjr%5C8ud!w%0DtF%09jA%09%20Lzto%3D", false, -786), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3AP%26WJc%5Cq%2F%23%24%3FnzD%3Ca.D%5C%7C2%7D5VLoD%25WXKNoKO%268yZg%60g(ZVV%2CoTe5tlkC", false, 153), "_uK%7Co)%227THId4%40ia'Si%22BWCZ%7Bq5iJ%7C%7Dps5ptK%5D%3F%20-%26-M%20%7B%7BQ5y%2BZ%3A21h");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("xC%26hm%22*%C3%87b%20z'%7C.C%7Ci2*%40k_%23J%22H%3Bl%3D(or%C3%91K%25%3E(PVFU~x%7D%7DjPhFa%22xz%3A_Ac%3BbjLPn1W%0D", false, 649), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("H%C3%87T'x%3Aavlr%7Dl!kYpY53%5D%09ZMh%7C-%C3%91%09C*%20M0RAH%5D7RxFG%5ERgtTw%C3%87b.%3D8~6%0A%22rn%20g%0A%40e%09M%40u(9%23S%5DS%7C%3F2Jr%24%3D6WjY%26f%5D%09xHm%5C-V%7Bc%C2%A9GM%C2%A95%23P%20%24%C3%91d%5E%C2%A9A%60%7D", true, -922), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("yGTS'OC%7Bk(!WB)ovbhMG2%40%0DWs'%C3%87WFr%20%26%23JhtJ*(%2C%25d*J%3AMkeuuyt%7BDWww!%2CguJYD!Asik%5E%3DDv%C3%91.IGbb%2C%2Ce%26oA6lg%3FZ%2FGo%0A'06C%C2%A9%23_%20r!i-dPo%3FrP%3A%23%2B7%2C5)m%24gN", false, 594), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%22%3F0l%3CP-%40p%3A%3Dj%5D7%7DI6cVd.%7CvqxkzXc8yoQA%24.)3qNO)D%40Zt~%7Cj5F'%3Avi%5DE%5E%5CgRH%7B9r%60T(%2FF%3AL%5E%400z62%5B%3F*%5B%2B%7DsF%5E-'*P", true, 353), "f%24tQ!5q%25U~%22OB%7Bb.zH%3BIra%5BV%5DP_%3DH%7C%5ET6%26hrmwV34m)%25%3FYcaOy%2Bk~%5BNB*CAL7-%60%7DWE9ls%2B~1C%25t_zv%40%24n%40obX%2BCqkn5");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%25_S15%60f%2C.On-kdKGMtbQQ%3AS%3DEi%5B%0A'6C%20tF%20)%C3%87t%7D%3B%3BG%2B%092d%3CDKbb8%7C%0AXR%C3%87P%7C%0D%3B%2B", false, -178), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("*%26fNyVkhokC5%3CEUeL8-.z-ctv%7BswS1b6bi%24eQ%C3%91%3F1!n-k%5B7D%2C%5D%7C3I%5D%5DXI6uAT4Ok*K(WC%3CBau%22s%7BL~i58%25*IozksVA!J%7Dv%3CtVp6'Y%3B%7D%60F%60%60%3Cmv0Sn", true, 32), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("yk%7BufIs.0WU%3FDMJj8A.%3Fd%5B%3Bq%2Cav(*0wwOs%7B%5C%3C%26%3F%7B%2Cq5k%3At.Y1", true, 7908), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("n%3AJRr%2Fj5txMhSR(M.%5D%3DrO%5BTp2Jn%3F(9M6%24Yg", true, -173), "%20K%5Bc%24%40%7BF%26*%5Eydc9%5E%3FnN%24%60le%22C%5B%20P9J%5EG5jx");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Nf(0%3DgVNEh%22%3BRkMqDG-D2DTO%40gL%7BHPuN%600%23%40%40D%2CK8lU3%20JS%5C%23ud1%23-e%3AR%2CS%5Cz!auMmXU%5C%2F", false, -452), "7Opx%26P%3F7.Qj%24%3BT6Z-0u-z-%3D8)P5d19%5E7Ixk))-t4!U%3E%7Bh3%3CEk%5EMykuN%23%3Bt%3CEciJ%5E6VA%3EEw");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("f%7C%24U5%3Dl%5E%3C1xI%3F8%2B%3Bx%2Fg_A%24Gov'5%3C'aQ*AtIM6_", false, -7138), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3F%5EJydlN%7CcAB%7B6%247(y%25%7B(N%3F4z%25%2B%5EuWN5Ayj1f9S%2F%40LC%5DVSX%7BnQR5PU%C3%91%25f%3DM9uU4lK", true, 994), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%7C%3Evc%3C4%3BMM%5C24c%5D%7C6%2B.1UE1r8%3A0W%5C9%5CcVO%26S%40B5cGeb0%3A%3Dq%5D65fk).iyHrD!%23R%3FVznAC%3F1z%40fhoiD%5BFrL(t~(Rb!", false, -492), ".O(tMEL%5E%5EmCEtn.G%3C%3FBfVB%24IKAhmJmtg%607dQSFtXvsAKN%23nGFw%7C%3A%3Fz%2BY%24U24cPg%2C%20RTPB%2CQwy!zUlW%24%5D9%2609cs2");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("qG-%5Dg%7DeOyDNKs%22tT%3CVuPsyFMs)%5E%2BK*p%25EScswj%7B.0k!YB4HzABe5'%26%3C%3DT%40t", true, -8832), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("lh%5C%25%3A%5E_z_Ol%2F%5DyIfp_tUJ-NN%3B%5C5%3BF-%20X1PxnG%5Ew)JN%2FTbCS'%3AmTc%23%2F.tPN!%40%3Esx%2B%3C", false, 50), "%3A6*Rg%2C-H-%7C%3A%5C%2BGv4%3E-B%23wZ%7B%7Bh*bhsZM%26%5E%7DF%3Ct%2CEVw%7B%5C%220p!Tg%3B%221P%5C%5BB%7D%7BNmkAFXi");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3D%24uyKL%3D)%26n%5E2LkxT%20llJ(t%3FDA9Xm0G1(IZC(SV%7C%7B)R%2FXcg%25iKVeUTfQ%22%5BFur%24%2B~_Z%263NOOH6%25ALB'V9MQ", false, -550), ")oae78)tqZJ%7D8Wd%40kXX6s%60%2B0-%25DY%7B3%7Cs5F%2Fs%3FBhgt%3EzDOSpU7BQA%40R%3DmG2a%5EovjKFq~%3A%3B%3B4%22p-8.rB%259%3D");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5B6B1K%09%24f_6%C2%A9%09(3d%C2%A9Y%3EuP8J%C3%91E%7CXpzK%C2%A9%C2%A9h%5E%C3%87FN", false, -231), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("D%3FD%2Ft*qFdo1xih%4004pU%5BpomB)NZLW%3AHmv-%2C%3E4w%3FbV6%24%3E6Nkwx%3DjyE%3C%2BDev%3E%5B%5C%5Ds%5B)n%5D6o%3B%2B7*z%7C0n(xywrt%23%3A1D%24guBAz0w%5C*)%7Bn%3DI8%3BRMAH%3Au%2B%20", false, 144), "rmr%5DCX%40t3%3E_G87n%5Eb%3F%24*%3F%3E%3CpW%7C)z%26hv%3CE%5BZlbFm1%25dRld%7C%3AFGk9HsjYr4El*%2B%2CB*W%3D%2Cd%3EiYeXIK%5E%3DVGHFACQh_rR6DpoI%5EF%2BXWJ%3Dkwfi!%7BovhDYN");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("K%23o%5BEJ%09Nd%3FGz%5B%7C%0A%25vLO%22f%C3%91.'bYPx%5DG2j%3E%2FC.V6%23%7B2DWu8ZqR1j%0D%5Cfw~Ldk%7Bm%7DTiW8r%2B%C3%91n*%5B%5EQrh%20iY9CAu%0D", false, 478), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Re4VL~Z-%3Amf%5C%40sht%25%3Chg%20n1d(%223t_1%2F4H0%24%3FqEm%26Yg(%7DM%60l%5DrpkZP-%2CUPEDY%2B%7Cs8z3%3B.%23'g%7B~otjNB%3E%60NG0fO%2C%5Do%2CcV56o%5EUyplT", false, 2506), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("*%26%60%26)%60%5EG%22E%7Cq%5CKm)9*%26UNfv)8RqU%0D%2Fwv)KB%7D%0ApV%26t%C3%87%C2%A9.aDmDG%C3%91WLQ%3AihO_%24V~%3DZ%3CwnUp%7D47Ug%7B%C3%87GBz%2C4%26vS6t18dw", false, -883), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("61e%7D%3AVXg%2Bp%23%3DYJ2b-%2FF1%2CXe%3FFkYj1V5(8%2BqTE%20PVY%5C1I%5BbfC%23znI%3A%5B%3D%20%5CEz%23%3CPu%2B9JXd(z6jQ-%40Yo81k5a%5CX", true, -647), "HCw0Lhjy%3D%235Ok%5CDt%3FAXC%3EjwQX%7Dk%7CChG%3AJ%3D%24fW2bhknC%5BmtxU5-!%5BLmO2nW-5Nb(%3DK%5Cjv%3A-H%7Cc%3FRk%22JC%7DGsnj");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("4g%23~7j%2Csk-%5D%3AK%205hE5_)10R8)K%5DAkz%25%2Bg%22-7ll1~", false, 252), "U)D%40X%2CM5-N~%5BlAV*fV!JRQsYJl~b-%3CFL)CNX..R%40");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("8%22YxJ9R7%3Ct%3Ba!%5DhwlRM9_sy_y5V%7D%7D%7CL%5Eoc(Std0tNEowU%5C-2z6%3AyXE%25N%208%3D%22yn47", false, -2145), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("LlB%2B)TTlmUKRf%7B%60%7BU%3BD5F%20TK%3FTF%3E%25AM%5CKS%3Avh%2FOPr%40Rtd%5CqLRSa%605fFa%26%3B8C%7CQN(Tb1gXRQb!Qme*%3C*G%60PX!jZEouY%5CIZr%3ASrWoVytMh5qKC%5BAchw%5D%24X1l0%3DY%3Dm18", true, 7399), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("24%3BM%23%2Bwsr%24*J%3A)9y349R%60%5D%3AGgzzg%22X%23A_8%5Cnrt", true, -800), "ikr%25ZbOKJ%5Ba%22q%60pQjkp*85q~%3FRR%3FY0Zx7o4FJL");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%40l54HGIi%3C7n-%5Crl%5D%24r%5C%7CWq8A%22%3CO-%5B_z'ij%23%26xfsAI4SexZiq%25S7%3F*%7BLKub8%23Zh%3Fw_%3F-Or1R%3C%2B%2618%3DWbX%26%24VwJyk~YHrZD%23m83s%7DM%7Ds%60L(-k2g0XHsW", false, -746), "2%5E'%26%3A9%3B%5B.)%60~Nd%5EOudNnIc*3s.A~MQlx%5B%5CtwjXe3%3B%26EWjL%5BcvE)1%7Bm%3E%3DgT*tLZ1iQ1~Ad%23D.%7Cw%23*%2FITJwuHi%3Ck%5DpK%3AdL6t_*%25eo%3FoeR%3Ey~%5D%24Y%22J%3AeI");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5E%2BS%3A'6%3B394!H%3CI%5DvZ%2F9njm73%24%7B%3DXq%20~7M%3C", false, 42), "4%60)o%5CkphniV%7Dq~3L0dnD%40ClhYQr.GUTl%23q");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Mt'-3s)*p%0AH%0A%0AzD%26Z%C3%91p(%241)%3A%3C23Lv%09%0A9'%3Chd%C3%87%3E-%22%7D(a%3FXt%40%23cPPkUN%0A%09", true, 632), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("A%22%09b%26oKEQIE0H%5B9%5E2MK4m%0AQ5DR%7B%24h%09BbH%25LtRsl%C3%87_-9Bcp%C3%87%C3%91%3F7%23_0e%C3%91v%C3%87%5Escwy", true, 730), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("C%5DlQNM~OT%2Bs0_l_%24%3Eo%2Ff%5BgxRs%26Fh~KQCm%22MXj%7Cxpn_j)6JlllFpGGiyo", false, 482), "%3CVeJGFwHM%24l)XeX%7C7h(_T%60qKl~%3FawDJ%3CfzFQcuqigXc%22%2FCeee%3Fi%40%40brh");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%0A%0AdyjC%3CE%C3%918%09G%7C0%C3%91B%40%5DOX0%603n~YN%0ABQ!%22%5D*%20%3Fbs6%23_l%3BfzD'~%5C~%3A6'%C3%87_%C3%91*HMd%22%0A%0D%3CH*~.cN%3B%22%40'by%227%26%26%C2%A9oj", false, -216), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("T1Y%5ED%5BN%5B.%3FkAhVGrDe%22%22F4%239p3_x%5Co%2FRJJb%3BWHrGFHNtXa4K%25Xy%20vU'hJzc%20JnI", true, -663), "V3%5B%60F%5DP%5D0AmCjXItFg%24%24H6%25%3Br5az%5Eq1TLLd%3DYJtIHJPvZc6M'Z%7B%22xW)jL%7Ce%22LpK");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("okTS%5CQ(W'%22o60%25N%7CA%2FsjXMh.iu*B%7C%265v2tv_R381!_v%23zChb'h%40Ei%3FM%40Q%2Fg0%3Dx*%25VISu%2Bs%5Cv%24Mip5(%24YH%229%7D", false, 6034), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C3%87%25oQ!t1TY%60W%09)(P4f~U0%C2%A9n)*%2Be%5CtcRk%0Aw%3B%5B%60%C3%87y%24kq%3F%5Ef%3Bf%25WU%09%3E1%C3%91%09Vn%3A%7B2SZ%2Ctb!r%C2%A9TLJ%25O%C3%87%7D%3D%23%0DSW%7DQz%3CHM08%0D%25", true, 543), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2C%C2%A9Y%23%40%3FC!%09ob(qk42%0D2C(4O%C3%91%C3%91%0DN%7B%0D%3CTLu%C3%87_%20%09%0D%60", true, 978), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("f0%5C7fVJvg%25v5%22%5D%5D%25uR%60__Hl3i9%3DzW%2B%2C5ivz%5BG.8rh%60B%2F%3FFgg%7D%5CD%5B1c%40QFY%202%5C!g%7BL)i61%25Rm9%7C%3BexMg%2C%7CE%40W05~~d", false, -158), "Fo%3CvF6*VGdVta%3D%3DdU2%40%3F%3F(LrIx%7CZ7jktIVZ%3B'mwRH%40%22n~%26GG%5D%3C%24%3BpC%201%269_q%3C%60G%5B%2ChIupd2Mx%5CzEX-Gk%5C%25%207ot%5E%5ED");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%22HR%3A2i29pk%3ECgXX%C3%87vHy7fD%25_%0Aux%C2%A9BMR1%3C%0A4%0D%C2%A9P80T5R3f%5E%3D%C3%87Vi%3B%3C%09L%5DzCp%C3%91z*C5%2CGw%C3%87%C2%A9RXs%C3%87-68%5CGd", true, -1009), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3Cdg8E%3Dfbnoq~%5Bd7F7Bx%3E-EuA2a%5COc%60mPCT%7BFs_%7CQ%40vHl(gm%7B%23~XMlOM.vw4kD1%3Fzl%26N%5EA_%3E%3EV%3A%24%3C%22Gol%5Dp2HB", true, 501), "V~%22R_W!%7C)*%2C9u~Q%60Q%5C3XG_0%5BL%7Bvi%7Dz(j%5Dn6%60.y7kZ1b'B%22(6%3D9rg'igH12N%26%5EKY5'%40hx%5ByXXpT%3EV%3Ca*'w%2BLb%5C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("2(%7D%5Ch%2F1qzFw.(P(cly%26Auat5sg%7D%25%3CvusOP%7CxK%3D%60e3%5B28_%5CNW(bsCVQeTzu%60i%24(v%7B%5C9K7%3AOA%3F%25eu1DO)u%3FBIrw%20QQRur%5C!c%5DhYU7x%2Fd1Bkb%20k%40E6", true, -6286), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Q0Sq%3A!!U%40%7DSwE%23%5E%23s1iU1Z%25aZQV%5BeJ8%2C%3A%24%5B6L7%2F%60zOr%3C%3A%3E%7Dj%40j-1.3Dcw%24B%60WylWBrC%3FrCpO78MmJ7r0SCkB%24ZdZ4H%2B*J1)(V%2Fj1", false, -2970), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5DDPl)a%3Eej(%7B1(%40F%40tZ%5ElUcWMCznq%7Cc*n~Pr5TiC%5C%22Jh%258Q%C2%A9L%40A%2FA9%0D%7B%5B%23.znd3dlnL(w*1%5Dj%C2%A9!%60%25%23mJQ%26%5EL4%5C3aOL.WH.Pi%22%5BX~hw%60bX", false, -343), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("e%22l%7CJXl%3B4V3jr%3AIF)%23cvV20%23%3FR(q%247yt%5DM%23%3EpnS%7B_U%25%3EwOT~%2B~%7Du'Akh%2BNh", false, -690), "~%3B%266cq%26TMoL%24%2CSb_B%3C%7C0oKI%3CXkA%2B%3DP3.vf%3CW*(l5xn%3EW1hm8D87%2F%40Z%25%22Dg%22");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%242UaJ%26F)20pct%C2%A9%60J'(gS%C3%91%5E%2CLn3tC%23PaM%5Es%40g%3C%5CF%5D65Zw2%09%26iP.rM6%5BanM", true, 351), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Jwi%26T1ocY8r7kwaZE%5BHsdX9%20pky2L-c%2Fj-4uB'-'2o%7D%7C%5EP%26%3F0f%22m%24Apz9%20qz5VVwW0h%2FJ%7BRW6%5E%7D7B8BwhwNh'4PpA%7Du%3E%25CC%3D%25_%20d", false, -879), "b0%22%3ElI(%7BqP%2BO%240yr%5Ds%60%2C%7CpQ8)%242JdE%7BG%23EL.Z%3FE%3FJ(65vh%3EWH~%3A%26%3CY)3Q8*3Mnn0oH!Gb4joNv6OZPZ0!0f!%3FLh)Y6.V%3D%5B%5BU%3Dw8%7C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("j5i%2CYc1KW%3Bf%3EE%5ES%2CD6RUE%7B)Nq6s%3FF~~yMd%20%7C~'ve%2BHy(k%5D(%3B2%3EU%3F%20%3Cr%3Bs(t3%5DcBW((dY%2Bd%26%20_ahPsvRZTM1%22%40JN", true, 968), "%7CG%7B%3EkuC%5DiMxPWpe%3EVHdgW.%3B%60%24H%26QX11%2C_v2%2F19)w%3DZ%2C%3A%7Do%3AMDPgQ2N%25M%26%3A'EouTi%3A%3Avk%3Dv82qszb%26)dlf_C4R%5C%60");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3C%2F%3F)S%60T4a%20D0%5Br!jOqk%25I%5Cx3U%23*dyRIi%5BRClzD%3F4%7CjTTP_55j_%3F6Pxq%3ETyq%2B%3AG25bwxY*JGzkv%3Dd%5E%60G%25%24%24L%5B8Pd%24-GNJW3%3FK6TpE%25GLg%7C%20o2zS", true, 7595), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("ND%5B%40c%2FM%2FW)Ag%3Ei%5EV!x%26!waedMm%23H%5D5%2F%3Bc%2B%40%3A(%5BL5%24(LtyZl", false, -176), "%406M2U!%3F!Iz3Y0%5BPHrjwriSWV%3F_t%3AO'!-U%7C2%2CyM%3E'uy%3EfkL%5E");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("8%2Fu't!%C3%87sk'%3D%40O%09wM%3B%09F7e%234Dp4vM2)MZ%2BQ3-!h%232b%60y%3CB%24%5E%60S%7Bdf%5D7gMN%3DkO%60%40%3E%2CW(4s%20nRTsqSZX%3FXR!*%5Bd(dF8'h%60%40UL0%25(K%2BC(%3Dir%3Co9", false, -430), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3AbT%26fI%20H9pl%3CXJL0M*%3D.cCvxi~X(xO*hFi%3DFW%3C~%3A3T", false, -9349), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput(")%5CU_%7DRv%C3%87ey%C2%A95~hsh%23xu%3C%25)%0D%26%3Ba%C3%91%5E8%2F%3D%0Dk%3C%7D%0DB%2Ce3-~yM%7B0)FXHb%C3%87OoX%0DVIDtf7g%3CnU3A6PBb%40K9A%2FI-%26J%3A_*%5B%25oX%0DE%26%20XZt7%60J9%2F", false, 519), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("eOv%60mgSLn7F%22IpeHu6%25cYmQft1RLdxe1t", false, 1919), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("w%23%5DjrONMJ%2F9aiMG%7C%5EyCACw%2403Fws%7CohMOhX%22%5DAUnBm%227)za)%2F%5C%2B%5CIvR9g%254uD%3Bo%60FhA%7CJw1q!k!xUBr%3AP6c4%3BzPGt%5E6%3A%23%3C%5Bvmr%5DXMt%25iKsa%3F%25", false, 941), "!%2Cfs%7BXWVS8BjrVP%26g%23LJL!-9%3CO!%7C%26xqVXqa%2BfJ%5EwKv%2B%402%24j28e4eR%20%5BBp.%3D~MDxiOqJ%26S!%3Az*t*%22%5EK%7BCY%3Fl%3DD%24YP%7Dg%3FC%2CEd%20v%7BfaV%7D.rT%7CjH.");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("MoD%25Ck%5C0z%26(%7DZ.%5B%5D%5BA_2pqaajC7V%40pPE%5Bp%2CShje%22rI%24z%2FZv!)%3C%3FOnn%3C88jKo%3ACC%2FP(%5B%3Ew%5Cp%3B%23t%5B95d)qQh%20Qqg2%5CS5%23i*%5D.-S%5CiEEmVQ%3C%26%60E%7BY7F%3CLbJO", false, 953), "JlA%22%40hY-w%23%25zW%2BXZX%3E%5C%2Fmn%5E%5Eg%404S%3DmMBXm)Pegb~oF!w%2CWs%7D%269%3CLkk955gHl7%40%40%2CM%25X%3BtYm8%20qX62a%26nNe%7CNnd%2FYP2%20f'Z%2B*PYfBBjSN9%23%5DBxV4C9I_GL");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("GU%0AeH%C2%A9Uv%23(W%0A5OEp3EWWsQW*36iSb%C3%91KFKLtKP%C2%A9F%3E%C3%87%C3%91%5DMESQ)%2Fny*xa%0Amah%C3%87t~%2CR%C2%A9%C3%87%C3%87%5C%40d%0AvuM%5C", false, -282), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5DLHK)b-3(%2CRey%7Cas.iXw%3Etj%4088zEh%3E%3A0UH", false, 7840), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("4SK0gz)%3AND)Hg5NFL~h7rJ%20Y%5D*aYz9W7!pv%23%26hqWnA%2B!-FomqLSE%3A3%5DL_%3B%3FMx%3BQ%5BA4%2BcV5Ry4A%2Cutg%3B%25O5", true, 1825), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("vNMu%5E%22G8-DZmPftlh%5ESL%2Bg%604%22Uh2CWk%40(%2C%3C_J%23ZG%26-JxMm%7CMrzCfw*IdO7zox6lwUwXB%5E%3C7RaZ-dO5~F", true, -6934), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-~L'V%40OOf-%5B_yc%20%23Ef%2Fsp%3F%3E%2C%3DZm%23(0E3V90lc7Sl%3F7t8%3FW%7C4x%60uXKcP", false, 7010), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("X%22F%26D8cJ%40XX%5DZ%7C!vB)%0D%3B%23%C2%A9%3B%269rA%60Y%7C%0Dh9aQWRrBOZ8%20y3Epr%C3%874VWp9O(ibPJ%2C%5D%25)%60BY%25i1%3FI_%C3%91%5E%3B%7Bw%0Dlgc-Bvo%C3%91Tpv%C3%87%09wPET%3F.b%0A%5Ep%C2%A9cdJj%3B%3A%7B%23yyiGGG%3A%3E%C2%A9s!H3!bk", false, -522), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("A%3B76lK5U%3B%3A%3Eh%2CsbCrB4vu%5By%3Ei%26q%7DMw%22%3C(%3F%23TUQmVX%60*%3E-M5!5E3FPJP%25%26P%3C%3AYu%3D%60%24%5BInMc%22mGws!hj1iRK%409ID2Ma*T%3BA%3CH)(%7CibM%22fA2%5DUiPudV%2Fk_c%40-", false, 751), "JD%40%3FuT%3E%5EDCGq5%7CkL%7BK%3D%20~d%23Gr%2Fz'V!%2BE1H%2C%5D%5EZv_ai3G6V%3E*%3EN%3COYSY.%2FYECb~Fi-dRwVl%2BvP!%7C*qs%3Ar%5BTIBRM%3BVj3%5DDJEQ21%26rkV%2BoJ%3Bf%5ErY~m_8thlI6");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("fI-'J%5DG%7BF_M8t%C2%A9Hbw%22%5E%7Dli%C3%87zWT%20%4019nWtrWKR%5E*~V78U.2H%3B%60%7D%3A%3CDSF%2CJ%7C_NG~_%3B%0A1%3AX%40fv%5C%3EDl6d%3E(%2C%3C%7D%25En00%5C'L51%22s6k%5Bb!uQM%5DbxK%5CQ62OJ%24Sw%0D%24v", true, 917), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("3Q%20%2FrC'Ne!R_C%60%5Bda%5Ck.DVE%2CAyk%7BaY%40y)_Vjr%25AE_Yk%22%7D%20NKy%7B%2Fv%5BrG7V%3F.933b%3DH7RK%5DN%3D3~%5C%20KkidGY-mf%60%2BpLI4tp%3DRgQ8", false, 399), "%20%3El%7B_0s%3BRm%3FL0MHQNIXz1C2x.fXhNF-fuLCW_q.2LFXnjl%3B8fh%7BcH_4%24C%2Cz%26%20%20O*5%24%3F8J%3B*%20kIl8XVQ4FyZSMw%5D96!a%5D*%3FT%3E%25");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("W%7C%2B%7B%3D7~L~%23bHLOeB0-c%7C%7Dy%3Ez_VMokiGuKU6Y*82fb%22KoST6_%5B%26XBRf%7D%23P%24pWI%7BvGj%2Fkv%2BXY%3DH8%2CrPJtW-L2Y%7C%3BX%23~O%22%5BD%3Bc'56op7)V%60)4o9Xozwki", false, 6752), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("RQ.%2BJwcxOk.%3D%2Fr*a!%26wd%2B%20bm7s%3DtL-M80%7Cw8r%25k%3B%20d%40DX%25%2BdSF206b2R7J%3CA%5EaYM!%60%3Baz~I%25%60C7-%2Fy%2B%20c.V%2BB", false, -920), "43ol%2CYEZ1Mo~pTkCbgYFlaDOxU~V.n%2Fyq%5EYyTfM%7CaF%22%26%3AflF5(sqwDs4x%2C%7D%23%40C%3B%2FbB%7CC%5C%60%2BfB%25xnp%5BlaEo8l%24");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%40)-.'e9z8*fRo%3DN%24'qIOVQ%26%2B%23w%3CMP%5Bk%3Ac'%5DVy%5D90Z%2Bf.9%2BY9G%5DQn%5CP", false, -649), "0x%7C%7DvU)j(yVB_-%3Esva9%3FFAuzrg%2C%3D%40K%5B*SvMFiM)%20JzV%7D)zI)7MA%5EL%40");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("c%C3%87ZOy99%3AF%3D%25TU!%23R)NX%23%7CM%09h3'hi%5Dz.T%5Chcz)y%20q0lgL%C2%A9V%7BH%C3%87Gm%26V%60hj1N%23Zhz%60HIZ7r%2B%3DnG%7D5xW", true, -809), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("KJr9%5EqEBEy%3BBG'hjP4B_%3BZh%3Er%2B~N%3EqK3%7Dvy1M%3C%3E%23dJpdBb9R%2Cd%7C%5EIr%2Fy-RfvV4z07%40%2CEozt_%23LGc0lA1G%5E%22k'%3BBtLQUqdJKqV%7D'-%3Dyc%7B%7BR", false, -9560), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Pb*ayL%2C%3Fy%2Co%24I%20s%7C(994Id%24S%24K~b)g%5Es%2Fs%23%2CstuL%5D%26%3Ck74%3FG_vS%7DgcD~kqcK31W", true, -402), "%3ALsKc6u)cuYm3i%5Dfq%23%23%7D3Nm%3Dm5hLrQH%5Dx%5Dlu%5D%5E_6Go%26U!%7D)1I%60%3DgQM.hU%5BM5%7CzA");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("X9xUV8D)t%7C%22)%26%5Bj*%2C%7D%5D4IM%20%2F24)a%40L%3C'!uMlH%3DSi0%3E1o9S6F9mAjKQUF%203Ft'u12vJ!bP_%3F44gPW~c*d%5DS%22%7BSJ%7C.%7CFi)G%2CkLt%3C%3Elz%7Cf%2C2~Lef%2FM%40", true, -8368), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%40'm_2D5onv%5BiAe!C%7C*Zu8%3AcCjyEayH22%40MkB%24z%7DP%3C*%7D%3FP8%26OEz%7D%7D%3ChqP%7BmmosE%3FS%26%25s_M%3FG.%3E5s*%5E%2C7L%3Cbfry%5DlK)5j4%3D!6WN-%3BO%263q05B%7DLYuPp*FOVB%3CxW%2C%5D%60%2FY", false, 4823), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("2pfd_~%5DQ%5B9b%5B%60%2F%C2%A9_C9ot3C-%23%3F13%2C%7Cl79S.U%0A.hEU0%09%26Fi%C2%A9J%C3%87j%3F%0AkM%09%2C!eHOON5sf%3Ad%C3%872OH%2B%60K%5E%2F%3AY%2CYK%23%5B%C3%91QM%2507lA%C2%A9u!8wUSS%5B%C2%A9(W%5DT%23*jBc%7Bqx%5B%0DwOQV%3DtD%3D'3%C2%A9K", true, -661), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("O_fCh%C2%A9%0DV%7D%2B%2B%7ByBX%2F%5DiSZ%C2%A9%0D6Ca%7B%C3%91%0D%0A*h%09%3D%0Aw%5BO%C3%870", true, -556), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("~7Dw%20N%5B%3DTC%25N.%3BLzbkr%236T4*U%40%7B%3An%7Bdd%7C)XM%26h(6%2BW%3EL%20jCO%3Dtx'T%3EW9%24e*%2BzU%3DxTm%20wqy%5CWI1yU%7B3PUji6g_F%2Fm5rGDGfRcm--", true, 2405), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("xq%5DmzuK%C2%A91rkD4w%0A%0DhbT%09Nx%5E%5Bo%3E%C3%91%3BQ_F'XoH6~w25D%C2%A9CvU%3A%C3%91fbMWZ", false, 497), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("0*V%5Dz%7DIbk.o1fj%5Dhj3oq3E(hw~fy-Hz%3AVq9H%40r95%60%2C%24Zm%60m%5E00cP%20fS9TS1d%7C)SChZ%5D", false, -24), "HBnu36az%24F(I~%23u!%23K(*K%5D%40!07~2E%603Rn*Q%60X%2BQMxD%3Cr%26x%26vHH%7Bh8~kQlkI%7C5Ak%5B!ru");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("L%3C%22-StL_Q53qd1Je%3B%25!Z1XrA%5B%C2%A9%3D%24S%3F(gEM%7C8b850tv%60%5BjJS.%5E%C2%A9OH%5D%26lg3pv%25%2Bg-8Q6ye!%26%3BiKqT(%25x%3C%3FUy2.x%26F*0LCy%3EcpuLD*a1oXf%3AC%26Sh)a%60CYk9%3CvaTN", false, 162), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3BFBPV%3EP%3A8%20%60xY_Xx7yy)%3D%608%3F%3D3gXCPc%3C%23.%7CG%3A2bO277KLl-%2F%3Ep%7Cx.kg'%20v4%26re%3CGSv%5B%40t%5E5", false, -6411), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-FaG%2CxhCWIN17*%3C.%3FAeA(_ZwN_YF%40pfm_", true, -407), "q%2BF%2Cp%5DM(%3C.3u%7Bn!r%24%26J%26lD%3F%5C3D%3E%2B%25UKRD");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("a%7B7-%26!v'%2Ch~N3%3D%C3%87%C3%91S69S*%5C%2CGJmn%C3%87e%09%5BD%5ExYg%2F%C3%87%C2%A9%0DU%3Bw%5E%0Am'Lr7w%5Bmxdt%22-%2C%09%C3%87", false, -587), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("v0y%7B%3FV%3Eh%5D%60a_e%20e%26%0DahS%40%2B%3Df%090gxm'%0Aj%60%C3%91%2B%5E%0A8%C3%91Z%C3%91%0A*j%5Csomskej%2B%C3%87yEx%5E'7%C3%87%C3%91%C3%87'S%3F)%25z%C2%A9%3A%5B2R%25RM%3C!%2B%09", false, 471), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3Fp*u%25%5DBk%60Ky!)%2CHqXC7(KI0Q%5D_%5E%22XYr')e%7CsTZ%3EgF4YuKjKy5tX%3En).%5E%22WxFL%2C%3Fr%3AI%22)%24_%26vcbR9O411O%5BlpuG*%5D%C3%91Lhp%3D", false, 275), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("D_HcvC%3BpUL%25%3F%22%5C7WZi%252%25Zs%2Cb%26%40%5EUG%7CKvmzSKO%3FZC%60bo1%3F%2BI%2CCA%23KNGah%5Bdnv%60G_p%26yQyVB%7DV%5BX.Q8f7(", true, -322), "~%3A%23%3EQ%7DuK0'_y%5C7q25D_l_5Nf%3D%60z90%22W%26QHU.%26*y5%7D%3B%3DJkye%24f%7D%7B%5D%26)%22%3CC6%3FIQ%3B%22%3AK%60T%2CT1%7CX163h%2CrAqb");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("GOy%5C-%5E%7DVSH1%20A%3F%3D%40yN%7C27eh%3Cs%2FN)Y%26CN1d%60!%3D%201'yh%3C%3EpQLzisbq%7CE%5E%5B6y0%3B%7BPBVTk%2Fqa%60H~%7D%209hO3%2Fn%3DhGasUE%23%5D9%25%5BW'Ey%7CcZl", false, -3864), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("n%7BK%3F%3C%60Z_jch%3CP-daJ8tG%3B~D%20%3ER_%2B%5DB%3D%7CUv%26%24o1%5DvG%7C~%3E%3C%3FjxAP%5CO%2F%3Em%2BQH%5C%20.8RA%3F%260%5C%24*o(%3Blh.QB", false, -905), "AN%7Dqn3-2%3D6%3Bn%23_74%7CjGymQvRp%252%5D0toO(IXVBc0IyOQpnq%3DKs%23%2F%22ap%40%5D%24z%2FR%60j%25sqXb%2FV%5CBZm%3F%3B%60%24t");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-Ukww%2C0xr5%7C-d%22J.%2C2%60bW%7Bp%5E18hU%60Uq%3DwEW%3D%3BA.%3FT%25G%7Bx%5Cr9lClW%2F~%0D*%5B%23Rm)c%5EZcW%3EH5%5CHu)NZOY%090%3D%23L%C3%87htb%5B%C3%87.Wy%3EARW%26%7B6%09RV*ER~o", false, 131), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-%2B~%3CXyZ%5Cip%C3%87%3A%40%3D%5Dv%24%5C!%3C%22'%09%5BA%2Fe)QY%25%26*Ji%25B.%7D%C2%A92Yb~5S%C2%A9*dkYX-%3FdRkJHD%C3%91bgA%2C1ZgMl%2C%C3%87m%C3%87mOQ-Jm1r%2C%0D%2F0%C2%A9%5C_Xp*4%40%40%3CWZ7YG%C2%A9Y%7C%C3%910%C2%A9%3B*c%C2%A9e%C3%910!V", true, 346), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%0D%C2%A9%20tchK'%C3%91%3D%7Cl'%5D%23F3h%3F%C3%87%5C%C3%87q%2BO%0Dk5F%09K!%C2%A9%C3%91%0A%25K_8!c%0AFo%09%3A~8", false, -836), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("DFpO%7B%3FMS9fbfL%5C%7C%22CD%26%20rK7%7CnxL%3AlozR%40%3AQ0E%2F%24~%5Cf%3Bh%26*B", false, 540), "bd%2Fm%3A%5DkqW%25!%25jz%3B%40abD%3E1iU%3B-7jX%2B.9p%5EXoNcMB%3Dz%25Y'DH%60");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5B%22XMjq%5D)wh%24%25'nzcBf%2B7!6V%3D%7C2(9%3EQR%3EES%5CRux'Oz%5EgOee2g%5DmQL-F7%23o'R3%22(2drAAC4zQ%22u%3Fup%2BG)dmoOW3t)%22zVJZ1vUU%2BK%40TNWD(", true, -10107), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("4iofc%26(iSAd%3C%3B%22A34%2C%23%2C%7DK_0vk%2BRnt6e%7B05%3B0%7DY%5BRg%20lrOSKF939%60l%5Dme~%24lE.%5EO%25%2Bef)UVfuB'(R!PS(rAD2%26ZK(G.dV5%3BRy~%2F8%3C%5CA5Dm40%23y%3E(4Vf%3BxN%3BI9WO%5C%3B%3D", true, 450), "zPVMJlnP%3A(K%23%22h(yzrird2Fv%5DRq9U%5B%7CLbv%7B%22vd%40B9NfSY6%3A2-%20y%20GSDTLejS%2CtE6kqLMo%3C%3DM%5C)mn9g7%3AnY(%2BxlA2n.tK%3D%7B%229%60eu~%23C(%7B%2BTzvi%60%25nz%3DM%22_5%220%20%3E6C%22%24");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("hpR%C3%91'%24%2FC0%2FVEiVfA%3BT1l%60z%7C~%20%0AZlGW%C3%91p%3Eb.%25Vq%3CEz%C3%91z9%C2%A9%24RL!EYiqxXUU35C%C2%A9t%C2%A9g%25G%C2%A94J%22%5Edp%24%C2%A9%7CNX%0A", true, 278), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("L%3F%3CgT8C)a%3Fcqo%3C!xDO%5E.LkLfqlG*1cd%3EQ!oH_1yCY%7CJ0~Z)%40mV%3E%3D0AKwu%3FJp'x*na", false, -6749), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("e.%5CDn)%3AFkg%3CpIo*-!C%2B%3CxC%7DQO%3E6%26h%7C%5E%3DbB%40zd%2BN9yQUZJJ%60raRW15%23%2435l%7B%2CVXZd4f%26)4%5Cq!)K%5BAl%2Ch%60W%3BA%7B5'%40", true, 802), "0X'n9Sdp62f%3Bs%3ATWKmUfCmH%7Byh%60P3G)g-ljE%2FUxcD%7B%20%25tt%2B%3D%2C%7C%22%5B_MN%5D_7FV!%23%25%2F%5E1PS%5E'%3CKSu%26k7V3%2B%22ekF_Qj");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("~%C3%91%5EPU%09%C3%91w%5E*b3ckPUe-%3Ba%40GGeJ%C3%87%09%40%09xWf%60Du)Jd%5Exqe%C2%A9SQScGAUb%09u*n%5BrqX%22aI%093%0A%09SC%C3%87ke%3C~%3EnqJ'c", true, 695), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("*_Yi1.%2F%5E'~_O%2FJ_%23zHPf%3DV_(%3EncW%26Q%3Di2.edKE%7CGntOR-ea3rhsL6u", false, -51), "%5D3-%3Ddab2ZR3%23b%7D3VN%7B%24%3Ap*3%5BqB7%2BY%25p%3Dea98~xPzBH%23%26%6095fF%3CG%20iI");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("d25%2310DTlxyDvj0%5CBI1(VR%3DboLAVJ9Qy%7D5cio'%25Xy1V7%2C8U%26KOR%3EjYj%3D%3AJZ*YB%3At%7C%3E)w.7M%3D%7Cz.", true, -252), "%26SVDRQeu.%3A%3Be8%2CQ%7DcjRIws%5E%241mbwkZr%3B%3FV%25%2B1HFy%3BRwXMYvGlps_%2Cz%2C%5E%5Bk%7BKzc%5B6%3E_J9OXn%5E%3E%3CO");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("dLrN%3D.1p%60%0A%C3%87kkqLxIR'gZILko%3F9s2qVrg%5C5_c)t~%5EXUU8_b%7BssX%0Di%3Bj-%3E%5D%3Esx0%5EH%2F)fY%3CNvo9%22.M%26%7B%5E%5Cf%40%5DK%0AY%3A!%2FcP~3eLm", true, 79), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("XIlyYOc%5C26fx%3EY%60%3C_x%5C%5CF4v%7CWI%C3%87EQ%7BSQRQax%3F*%25L%20~%C2%A9k_tPt%23ITy%0D%3AL3%0A%3E%0AJ%0DM%2C%7C%C3%877wb%60PaC%0A0*%2F%3F%207-%60%2F%26e%250%C3%87X%26%25%2C%0A_.jPUkTsL%3A%3EaB%3FgIek2%3DlSmMq-%C3%87%3DdUY%09i!", true, 586), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2BdT%2FE%2BY3Gm%7C9HP%2Bb(eTIxS%3EB%5C%2Cr%25%3F4d%3A%2C%3Di%2Csj2DM%2B99%20%3E%60%5Ex3'ng%7Bw%5C8gsN%25)V%256F%3A%26%7DovS%7C3%23'fSr%2B.%40b6J6%5DLDN%5B%2Fx%3C_M%5DX%20Ll%2Fp6o~MJ)F'2bci%5CU", true, -7125), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("BL5%40TQEm%40P%220F7-.CxB%25D.%223%25J0YS4yB%2F(%2FG*b2P.nwU%24zX-J%7B-1%3B%20vM8_0b%3Bx0%5Cj0nL%3E-wUP%5Eej%5DQ)%5D%40", false, 213), "%2B5%7D)%3D%3A.V)9jx%2F%20uv%2Ca%2Bm-vj%7Bm3xB%3C%7Cb%2Bwpw0rKz9vW%60%3ElcAu3duy%24h_6!HxK%24axESxW5'u%60%3E9GNSF%3AqF)");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C3%91%09Qmt%7BY54duX%40W_FD%C3%91%3E%C2%A9%0D%22%09C.y%C2%A9Y%7B%2CbHM", true, -43), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("I2%3FV8%C3%91sLF)Hrd'K1mm%3Ey2NEF%60Z%7Buh%7BO%C3%87bL*xp%3EP%60dKM%0D%C2%A9t%0Dtm%0D5QI3", true, -313), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("!G%2CyH'pf2P%224ZD2AZo%2F%3COQbtuuA!%3DP%3D%40JzN.%26k%26PV%2CqlAxY5tp%3CAoR%40~%3E%2BQ4wRUt%2F9M%7Cc%23%26%23D9AjYicuC)%7D~4%7B%7D0%40%22jNz)%3AM%3B%25%3Cn4%5B%3DgXcQh%230%5EP%5B%5By_mu%25-9MY%5D", true, -986), "%5C%23gU%24bLBm%2C%5Do6%20m%7C6Kjw%2B-%3EPQQ%7C%5Cx%2Cx%7B%26V*iaGa%2C2gMH%7CT5pPLw%7CK.%7BZyf-oS.1Pjt)X%3F%5Ea%5E%20t%7CF5E%3FQ~dYZoWYk%7B%5DF*Vdu)v%60wJo7xC4%3F-D%5Ek%3A%2C77U%3BIQ%60ht)59");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("6LT2)S5~%20.%23zpIN%22D%23Nk%3C'C%5EN(s%5D%7CFr%22DdRW_z)'DrP!*%226XUbv%26t%3F", true, -405), "%7C3%3Bxo%3A%7BeftiaW05h%2Bi5R%23m*E5nZDc-Yh%2BK9%3EFaom%2BY7gph%7C%3F%3CI%5Dl%5B%26");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%26vUkh!4%3FZmi(xi%5B3(G_VA.B%60%7D%2CX%5C1Yd~%40ke%2CgYZ73Gf%242UChyZ(!(%5Dnt%26%3F%2BFW%7C4P%40%2F%5B%2CB%26tHP%7Dc%7B%23A%3C%40y%5Eiuom5~%25.L%5C%3C9u%3B6%23p%22Tbq%7CxkaV3bru.%7DJt%3C%7Bs%3A!%25)q-sx", true, -1730), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("uSs1Wz%7BU%40Zdb-M3%40ztl%5Dr%3BBfH%5B%5DPjzQ%7CMfdY'%3EN%404U0I", true, -6911), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C2%A9dmB%7Ds'%3A!*%7CE%23e%3DN%5C%3Ex_oB%24%7D%22%5C4CB%2Fd%22Ky(DBA-%5Cqnl7d-ZA%0Al%7CY%3E%0DF%3B%5B2rl%3F%0D7K4lQy~CMxvI-P%7BFB%20%5DgO%23%C3%87%3F5b%25h%3A.SlrA%2BZ%7B%7B8r5Ef%0D%3CvRrVf%2BZ%3F%7D239pzpBD", true, -330), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%7DgE%3C%5BU%3FimquX%3C%60%2Fwu1'iY%2Bcp%25%7D%3Dc%7B3YFo%2B%3EU)29", true, 41), "G1ne%25~h37%3B%3F%22e*XA%3FZP3%23T-%3ANGf-E%5C%23o9Tg~R%5Bb");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Sp7sec%60%C2%A9I8HViwU%0D!%C3%91j%7C%0Ari%3Ah%40!x%0D%7C-XH9-k%5E%3BUMyux%40(!4%24)zn%20_%7DF%2Bb2%5EriO(%5EpL%7BiJ%2F%3FWl%3EQs%40%3Dg%20%7B%C3%87%0A%26Z%22%25%C3%87%2B%24%3DlNc%3A%C3%87U%3F%2Bt*Ushu~2W%40%3E%2B", false, -527), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("6g%22S%C2%A9%26%40%09fCe8%0A%C3%91j)m3)kX%C3%91%0A%C2%A9Ei%C3%91-%3EMcg~F%20q%7BTeTLSTV.IH37%C2%A9%3A%5D%0A*6%23I%0A2%0A04%0AO%0A", false, -40), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-l%40H8n)%5CiXKL%5Bq9~!Q%7CqaJ)g%22s%2F%3CzIHx'RexB%24aGM%40%26%3AS%5EfSU9%24%5DG'%7CA%7CjvAap%2F-3rJT%5D!%23ase%2FCh%3BI%2CNDG)%22GjwT5~!'%3D%23h%2Bp9%7D4_iD~2%60qX7R%24-BR0_t%3A%3Em(", false, 4107), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("eqS%09%3F%3AbY-A3Y%C3%91%0D%C3%87i!%0D%0A-flrT%23tq~%C3%91o)%C3%91%09%C3%91%0D'%C3%87h4TO%3B%2C", true, -26), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("1%3C%3DZF%40Fa%09t%C3%91a%C3%91%C2%A9Ku7YZF9%3Bzj'-%C3%91%C2%A96KZ2", false, 877), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("q%2BXIrVL%5BzcER%09370fI%09%26h%3E73%2F4%20Llpt04%40IQ%C3%91%7B%3FM%2C5%7Cc%25%7C%25tDZeU%25%C3%87%09ql%0D%2Bc%C2%A9yB%3D7%605SNZyf.2rBY%3AEa%09v4%3CI%2FWS%C2%A9o%3C", false, 165), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("y%3Cg5n%5C')c-P%256q%5D%3EBI0!~%26%5EB1Cj%5DhN%40BEK%5B.lkSrhG-D2C7%3F8Wt%20oH)DZf.x%3D-G%3C9%3El9iQ.hHXy%40%25!%5DT%23iNntf%3F%5E7fN%259dO4I4E%5B%5Cp%20cJ-k~od%25%2C.8w%2FH9K", false, 1011), "%3C%5E*W1~IK%26OrGX4%20%60dkRCAH!dSe-%20%2Bpbdgm%7DP%2F.u5%2BiOfTeYaZy7B2jKf%7C)P%3B_Oi%5E%5B%60%2F%5B%2CsP%2Bjz%3CbGC%20vE%2Cp17)a!Y)pG%5B'qVkVg%7D~3B%26lO.A2'GNPZ%3AQj%5Bm");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("*%5E%2FL%20k~%3Adu%20)%5CSY%60'GDr(HSW%205dP%2BYk%26do--%2B%7D%5C-%2FbQ3y)tW--XtL9Xb7gUxqh%24%25KM%3E7!GLbf%7Dua%5E", true, -65), "H%7CMj%3E*%3DX%234%3EGzqw~Eeb1Ffqu%3ES%23nIw*D%23.KKI%3CzKM!oQ8G3uKKv3jWv!U%26s70'BCik%5CU%3Fej!%25%3C4%20%7C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("6zWLKsVn%5BTytI37.%24%3CoXJ%60%3Fs)Q%7B%3F%25EzfF-!%5B_~i8-A%3EvczTlTo%5C-Y-nG%20r't%23*P%3D%7DOM%2FH%3E_FE7kg-AV_W%3Ecb8%7BH%3A%5Dr-%22%2F!g'*(xDM%2CNm4ZJi%259n3FWUl%20cEmIH%40aGfK", false, -855), "6zWLKsVn%5BTytI37.%24%3CoXJ%60%3Fs)Q%7B%3F%25EzfF-!%5B_~i8-A%3EvczTlTo%5C-Y-nG%20r't%23*P%3D%7DOM%2FH%3E_FE7kg-AV_W%3Ecb8%7BH%3A%5Dr-%22%2F!g'*(xDM%2CNm4ZJi%259n3FWUl%20cEmIH%40aGfK");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("nn%26gyrx%3C4T%5Bt*Y%4007_.ay%60GqOdkl-7%7CegECIB82XN%5C%23y2_Hp%5DrZBg2h%2C6DnYvwTB6%26Qdff~FiFwVL%2BO'C%24e6O.~Xa%3CynL%3CB9L~(", true, -12), "bby%5Bmfl0(HOh%7DM4%24%2BS%22UmT%3BeCX_%60!%2BpY%5B97%3D6%2C%26LBPvm%26S%3CdQfN6%5B%26%5C%20*8bMjkH6*yEXZZr%3A%5D%3AkJ%40~Cz7wY*C%22rLU0mb%4006-%40r%7B");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("dI%3Cc'Df%25gMV%3A%2C%203%24uY%25'Io%20o%3DehTYh%3D%5BsbZp%7B%26C%3AY4lb%7CXdF'Zd-oSi)%5C)L2cb%5Er%24%5DGqW))%2Fgy%5E%5E%20RfpXN_t%22B*D%25t7%22%3AFdF9%23WW0%7Bq5_)z_B'4Ko-%3DS%7CWY%40k%3E%20%23", false, -78), "S8%2BRu3UsV%3CE)zn%22rdHsu8%5En%5E%2CTWCHW%2CJbQI_jt2)H%23%5BQkGS5uIS%7B%5EBXwKw%3B!RQMarL6%60Fww%7DVhMMnAU_G%3DNcp1x3sc%26p)5S5(qFF~j%60%24NwiN1u%23%3A%5E%7B%2CBkFH%2FZ-nq");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3Czl%3F5%60b%20sOGYLAH%24u%3B3qZ.gN4OAMB'tsX*gq", false, -3638), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5E%23.fOE%3EVjuv%3B(%26rY446FUuI7(6d9Mz4%5DJPjR5ocBQC%3Dbi%40)lt1T%24sb%3C%5BihAzhM9ycK~aNbB)PEK*%24TI%60%20e7F3", false, 243), ")MX1yoh!5%40AeRP%3D%24%5E%5E%60p%20%40saR%60%2FcwE%5E(tz5%7C_%3A.l%7Bmg-4jS7%3F%5B~N%3E-f%2643kE3wcD.uI%2Cx-lSzouTN~s%2BJ0ap%5D");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("4%60i7%40c%7C%3AxA%40%3Az%3E3vPU%60_j%5BuqP%5C%3Cd%5B1Gg%2BzN%3DlwA(r%40j", false, 1007), "Z'0%5Df*C%60%3Fgf%60AdY%3Dv%7B'%261%22%3C8v%23b%2B%22Wm.QAtc3%3EgN9f1");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Jj%5EB%2F%40aj%3E.I~wuKv%60%40DZ%26~7%7ByH%3F1%7D4K%26B", false, 122), "%2FOC's%25FO%23r.c%5CZ0%5BE%25)%3Fjc%7B%60%5E-%24ubx0j'");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%7CaLyM1OL%25ujQ6%3BIt%3EsGb%23r8u24J%2Bt'%3CLSsj_%2CN%7C%24%3CAfgB%2Cv%3FWH9wJ%3C%3CEMV%7C*%7D%3ER%2C%22lL2%3D%5B%40%5EOx4%3AOE%40!fn%5CmKB6GTF%2F!Ttlvdw61%26%4032%7B0cHu%60WM%3B7%5C)jC%7BM2G", true, 473), "z_JwK%2FMJ%23shO49Gr%3CqE%60!p6s02H)r%25%3AJQqh%5D*Lz%22%3A%3Fde%40*t%3DUF7uH%3A%3ACKTz(%7B%3CP*%20jJ0%3BY%3E%5CMv28MC%3E~dlZkI%404ERD-~Rrjtbu4%2F%24%3E10y.aFs%5EUK95Z'hAyK0E");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Xx%3F%40XagH7%22hFAkaTj%3B%5D%26lyA%7CefyWAlp%23NAv%5BF%20ZPrX%23%25%2CkEP*x%7C%240eAy%5Ekczn%3A%3E%22%3Dm!s-z3jvuhQ3W'%2Bc%2CfGyh%3DH2YEUi33i'%25yV%5Bc8y%3AC%3F9%3A%259%22MAy)%26H2%3D%261j%3E", false, -510), "%7B%3Cbc%7B%25%2BkZE%2Cid%2F%25w.%5E!I0%3Dd%40)*%3Dzd04Fqd%3A~iC%7Ds6%7BFHO%2FhsM%3C%40GS)d%3D%22%2F'%3E2%5DaE%601D7P%3EV.%3A9%2CtVzJN'O*j%3D%2C%60kU%7Chx-VV-JH%3Dy~'%5B%3D%5Dfb%5C%5DH%5CEpd%3DLIkU%60IT.a");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%23a9%3F2!XpgHH%22FQ%23Y%20baD%20v%23_6p%40%7B%22%7D65", false, -329), "O.ek%5EM%25%3D4ttNr%7DO%26L%2F.pLCO%2Cb%3DlHNJba");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("7hn%25%201rVbgr%5D%3A_%40%3EcU)-vnP73v28pom%2B!_T-%234%3AC*sY8AzIkA%3B'V8!x%2B8%3AL*J~mYt%40X%60%3C%5Bvc%3Bo_h~%2F7q%3C%26%3A%5BCboPt4(lq6gG(ZzLm0V", false, -6313), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Mp~H)Jcx%3AMEtptnqg%5Em%3Bq-1K%3D%250%24h'%24%7D*M1%24rx8ZPMk%40Ml%2BZzMc!%2CHj)WF~uP%7BI%3A%7B%26eC1~CO~%2B%7BsY%2B'9!!pF9%3Ba!n%2C0swVyY%3B94u%23'*j1nMSI%23%2B%26t8068E47g%2B", false, -10161), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%09S%24UR0j%0A3mUT%2C2%C2%A9%5D4Bhp_)%0A3570N%C3%91.j_2y%C3%91B%3FbT~*FUwhO(c%0D'M%C3%87razID-%3E4kY9", true, 784), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("4*iLVE%2CL%2ClV0D%5C0*q%40cK4%3F%7C(-snZc%25k1%3EHIdV!~d%5DTJMT95oeCb~Y%40%2B%7BI%7C%7DY-UoX00%26L%24-*%5Es%3CLu%7B6vV7ke'Kem%22en4G%2C~4%5C*", true, -1014), "SI)kudKkK%2CuOc%7BOI1_%23jS%5E%3CGL3.y%23D%2BP%5Dgh%24u%40%3E%24%7CsilsXT%2F%25b%22%3Ex_J%3Bh%3C%3DxLt%2FwOOEkCLI%7D3%5Bk5%3BU6uV%2B%25Fj%25-A%25.SfK%3ES%7BI");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%20.j'%5ED%3Cbo8sBd%7CiQY%3BT%26%25pD%7Ch%7BbJv1k%22Rj%20DB1%26a6%5ErTQgO%40", true, -172), "2%40%7C9pVNt%22J%26Tv%2F%7BckMf87%23V%2Fz.t%5C)C%7D4d%7C2VTC8sHp%25fcyaR");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("i1.b%261%3FS%5B%C2%A9!%3E9SEL%C3%91G%0D%2FD%5Eg%3F%3B%22%60bB%0An%09!%C3%87Vvc1c%220%C2%A9'g%0A3UnU36%C3%91%2C%24x%0A%3B%24%60XbR%24JLP%7BJ%09Ai7IvGU~%3BLYS%C2%A9bGe_%20K", false, -837), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("hO'%20%5C)%7CulK5%3A(%3F%25e5mDWk%2FE9k07nI.LF%2Cf!Ip%5D*VX%3BQ%3AU4%20O3Lr0AF3%7CAr%3Ed9%5D'02mq%3B%7B%7B%5Bs%3D%7CD_kV7I%40K1El%3BMh%25%23%2CG%40", false, -589), "%7Bb%3A3o%3C0)%20%5EHM%3BR8xH!Wj~BXL~CJ%22%5CA_Y%3Fy4%5C%24p%3DikNdMhG3bF_%26CTYF0T%26QwLp%3ACE!%25N%2F%2Fn'P0Wr~iJ%5CS%5EDX%20N%60%7B86%3FZS");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("IrLgS~M%2B%40L%20HOL_V%3D3%5BJM!f0Cm%7CB%3C%3C%3F%20%3E2CAclA%2C7gnsD%2B6%26%20mhto%5E%22JduS4W%2B%26_Sy%23e3Up%7C(CAjU%3Bn2%5E%3A3%5E%3CbI0mkxn%20LGf%40BPdP%3BUQ70*kE%60y2%24%40%5B%3C%7C3y4%5D1%3F%3D9F~%7D", false, 7329), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("PzxHx%7BF%267HD%404%5C%7B7w%5DF50t%5BZ-a%23~Uue%60(c*%7BL%5B%3EEFx%22Ba*h%7CN%5C%40%3B%5D~%3DVMNa%60W%25T%2Fk-%26R%2FIsbj4XI%3Ehp%23%40(5OEZS%60y4csJt%3E%7Bv%3D%25dU%26C", false, 2569), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5DYOsOW~x%40NdFBM4oY*k%2FTgF%209ZB%5CI3%5CXqLlDdzmz%3BNEp!M34bI", true, -694), "%40%3C2V2%3Aa%5B%231G)%250vR%3ClNq7J)b%7B%3D%25%3F%2Cu%3F%3BT%2FO'G%5DP%5D%7D1(Sc0uvE%2C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%0D(%0DB%0DU%5EJ7%0D%5B%C3%91!D%3B%0AV%2C)k(s)%23%2B%C3%87'XTt%0D!%3CA~%0D%C3%91U%0D", true, -312), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("oTi%22tJo%60PtozgGHU%2FqyS5nt%20CD%5CY%5D*Gv)%3EyNu-YYHYBt66fw(Nb%5B_0a_%7BoggBt", false, 1664), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("H5%3B5H%7C_Lhh4A'F11L9JBPdO%3D%3C%2Fw%60%20dc_TP%7DKK%3Frn%5BY3o%7Dr72Tjg~UI%24%22%7Bu8wd%7B%5ET%40%7Dtb(~Wm-'bxM.nybgH'%247IJ)MN%3Ek8p%60q%5Beft", true, -1618), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("wewZK0ZvAfVHx%5EUq%25F3%23%3B%604y%3CQ%2C3s)%3Cr%7CU4K4%3A%7DmpMZhWYi%5CVO%6027uGSnRhDtXY%22Hf%2BU", false, -211), "-z-o%60Eo%2CV%7Bk%5D.sj'%3A%5BH8PuI%2FQfAH)%3EQ(2jI%60IO3%23%26bo%7Dln~qkduGL%2B%5Ch%24g%7DY*mn7%5D%7B%40j");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("bY-J%7B4u%2BT%20%2BOLG%20Aqx*.y4_kD%5Dq(8DlHjEJ%5BG%40YKJ%5EcC9.%3DSlB%60%5D1(X%3Ei%26s%3B3%5D60V!cA", true, 4015), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput(")-%5C%3CjM%3F00%23z%40%2BqPbvr%20cXsUzo%40Y%3CShEq%7B4asYH.%265J%3Dz%2B%20CXeF(YCB_1x%201j%23%3Ct%60oJ4%20M63", true, 6948), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("qdtXv6%7C9il%3FqM%3E%7Cv3X%23_%2B%3Fk%5DfV22T)%22(%236C(%23%3D~A%266bC%3Din%22g", false, -1650), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("'o2Bd%5EO)%3Ci%3Bkbx6a%C3%87('%26g%5E%C3%87xZk%0Dr%0D94%24Uby%3AOwSo0v8%60(%2CeAxl37%C2%A9OAlFG1EOLEBt%5DT%2F%3Er%2CbN%200", true, -188), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("!i%40WLy6si%3B81%254Bo~cQyC%22%7Bb8rUV%2BGF6F%7Cvd", true, 6870), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("~t(On3n%3BS%26%3DJ%5C(%5Cp%5E11!at%5D7b.4**%3B%3DU!-%7Cj%3Aptgl%5DP_s%60N)I%3Bz*l'NkQ0%3A5%2C%228yJjwjcQG%60%7D%2Bn%26%3F%7CA", false, -1016), "aWj2QuQ%7D6h%20-%3Fj%3FSAsscDW%40yEpvll%7D%208co_M%7CSWJO%403BVC1k%2C%7D%5DlOi1N4r%7Cwndz%5C-MZMF4*C%60mQh%22_%24");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("b%3B%0D%5B_%23E9%C2%A9wKU4)OJuDp()ZVm0hzqPe%3BmXhuh%0AE~%5E%7D%26kKjq%2Cs%22ET%0AgsB0%C3%87%5DKzk%3B5.R%7Ch%3AVP23Y%C2%A9ZiKx%5ByV8W.z5%7Dc%7B7AU_f%3D%5BKx%25I%25%3F!OVb(7%5E%3F%40l.n%0D", false, -91), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("uPTiH'M%2F34TB%3Be~~EO1F%3B*PNM%26zqVyFF~%3BWu4%2C_3b%5C", false, -9905), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("sA%40byR(Q7S8-t%20Sz5vWLpC4zA%20S%7BVB%23WlHgXfDnD%2Cigvj2%24LZGf*u4OTnTkl%605P", false, -8130), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Yh1J%23%7DCk%24%7BDma%3FRg%260%3FtL1s%7DkyE(SVOwtYa*%7BuFTgbkg6%3AXP9H4NFI%2C%26%244sm%2Fef%2CQKz%22vH%5B%20%25%22!f%7Cq%7DP~g%3A!8%3B%3E", true, 70), "%40Ow1id*Rjb%2BTH%269Nlv%26%5B3wZdR%60%2Cn%3A%3D6%5E%5B%40Hpb%5C-%3BNIRN%7C!%3F7%20%2Fz5-0rljzZTuLMr82ah%5D%2FBfkhgMcXd7eN!g~%22%25");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3A)Rr%5E0Vl_%40%23V~0B*%3Al8%7CtQE~SfV)y1.%5Dl%2FqbyHd.%235Q%5C%40c%5C2%60%24%608%24TNU('9!H6H%3Bl%22i%5D2!k%5DMmI%3EL.%20w4i8Uk%3A.l%3BNS*hZ%2Cn", false, -741), "'u%3F_K%7CCYL-oCk%7C%2Fv'Y%25ia%3E2k%40SCuf%7DzJY%7B%5EOf5Qzo%22%3EI-PI~MpM%25pA%3BBts%26m5%235(YnVJ~mXJ%3AZ6%2B9zld!V%25BX'zY(%3B%40vUGx%5B");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2Fxe6Lt6T-m_!O%60(YI%5D%5DW%7B%269fHfG%5C_%60L9%5E%5CK%7Dn%3FMr_RZY%5EOre2B%3AbphNu%22_tlq4-u%26s)%5BD(!j%2FLk%3BKWi%22%3FC-5bCE%5B%5B%5DRIuqz2D%2C%243.%40N2f%22%2Cr%3E1w", false, 7984), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3ApurDBUsUr%5CM%3B2%3CP._*%7BVx%2F%2B%3F'YQ((2'.sx%3A%3B7*TXNM", false, 3017), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("(Cf_Pmn%2FWyEMi%25%25CE%26I)!Pg7J%20xHZ%20hU)c%5E%3FCSjxdkk2bf4S%25wlxoOZ%40815lWiSzhk%3DHfe.M8_xV%3D5", false, -747), "z6YRC%60a%22Jl8%40%5Cww68x%3C%7BsCZ*%3Drk%3BMr%5BH%7BVQ26F%5DkW%5E%5E%25UY'Fwj_kbBM3%2B%24(_J%5CFm%5B%5E0%3BYX!%40%2BRkI0(");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%26ku%205%5D(k~3Jnt%7Ct0%2CZw9%5B11HK8%3DT(wC(Cv~_a6%5EK%3Bk%264TQ%253o%7B%20%23b6%3E_CA%232", true, 7174), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("7gN5g.R%24fB!%240A%2FJt%3Fkjgj(tK0%25j%5De'd%3C%5E-Ejrkq%23aZbzsfYy%60y%3DL%3B%60%5De.%3CwqmxuMr%3C%2C%2C%3E%2Cs%40%5E", false, -587), "Hx_Fx%3Fc5wS25AR%40%5B%26P%7C%7Bx%7B9%26%5CA6%7Bnv8uMo%3EV%7B%24%7C%234rks%2C%25wj%2Bq%2BN%5DLqnv%3FM)%23~*'%5E%24M%3D%3DO%3D%25Qo");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("nB%60vV%5EgmJ*c0Vf'VX%7B4jZ%2FqG%2B%5Dx%5EkZKXk8g.%7DWOB9QLUKXcc*%3CsyP%24L%23UTpt%40DuG%26)uU~B2a%23glHsI0", false, 404), "V*H%5E%3EFOU2qKw%3ENn%3E%40c%7BRBvY%2FrE%60FSB3%40S%20Oue%3F7*!94%3D3%40KKq%24%5Ba8k4j%3D%3CX%5C(%2C%5D%2Fmp%5D%3Df*yIjOT0%5B1w");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%60%2B%24ZB%3A*dw%26Z%2C%5B3CK%20%5B'3yxS%20%606nv%20!)0uRsQKLbW%22-B0%3A%23%2B~%23PP", false, 4443), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2Bxf%2F%22e%7B_l0C%3Eh%7DL%20t%2Fg%24MLMN-4%3E-N~d%5BEYo6%60RqwqKy%3F_pOZ2(v~hO7ZI_3F.)%24'g%3FK%204%5D(6t%22m'8f%2CE(lA_g%5Dc%40%40vuhwfB%5E(4Lp%3D!_!", false, 1334), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("FeCVQ!mCg%2F~%24%2F!ZSftwW%22z~-%2FI-7xu%26T%5BT8_nJO6r%5DNLT%7B!PGk", false, -2945), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("(%2B-%3A%20no~8%60l%2CHl%3Byr%60%3C%3F%2B%23%269%23Ccz%5EJ%5C%23x", true, 326), "QTVcI89Ha*6Uq6dC%3C*ehTLObLl-D(s%26LB");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%23((V'yFdUZ3i-Uv-nz%24c%7Co%2B%3D8qw7EU0D2Fg%2F%25%23bQU7a%7C%7B%220%60j", false, -3735), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Q_xP%60n%604yuaqm%7Cu!r%23JU%3Cv6V%3A9)0eYx%5B22%2CTmp%60%7Cg%5EY%7CH%5C%22LJv%25eBN%3E9b%2BS%26%5D%2CMX%3D%24-%20'9Za(k6%2BeTgobb%25", false, 440), "t%23%3Cs%242%24W%3D9%2551%409D6Fmx_%3AYy%5D%5CLS)%7C%3C~UUOw14%24%40%2B%22%7C%40k%20Eom%3AH)eqa%5C%26NvI!Op%7B%60GPCJ%5C%7D%25K%2FYN)w%2B3%26%26H");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3B%7C%3B%3FUwR%24(C.%3FV%22%2B7IrS%2BXH%40EkPjc%22%7D%25%7DDb'0d%3D3%2B8)wy%2Fo4%3D0d%2FMQ8h~o", true, -570), "%3B%7C%3B%3FUwR%24(C.%3FV%22%2B7IrS%2BXH%40EkPjc%22%7D%25%7DDb'0d%3D3%2B8)wy%2Fo4%3D0d%2FMQ8h~o");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%7C77~f4xL%5ClnP%3A%22%3Fvt064%40zHn)q%09WxTT%3EQ'ky%60%5BL%25%5E%7Dxsv.-tNCX%3D%23rnib%3A%0D2o%22m'ogsL%20r%2ByA%5BJAZ%60Ge7%24%7BABXY2%25%23-V%C2%A9ej-Ny.3%7DXvF", true, -846), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("--%C3%878%C2%A9RwYXs%3Ds%C3%87%09G%40OW0%26%5Cu*42a%7D.1FY%22DuFKZ%C3%87P%3A%2CK%C2%A9r1l%3FFl%3BZQ5%C2%A9%26UR_4L%3CeojX3.4%5DbEvj%099ysBsv%0Dv%0AfKZ'Hr%20%5CO%3DaOo%26Hx%5BPN1%5BP!%24S%09m%C3%875%23", true, 159), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("yB6'%23'U%7B!hLM%2F3%23RL%5B%23*--l%7CUj7t5YA%7CLA%20Lejw%7Bb%26f.oW%2Fnp%3A%5B%3D0)8%3FbRC*TJ", true, 3932), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%25vWOaejj)E-HH%5BA%60UeD%7Czq_*8%5Dsp%20AMn*vLo%60NGUA%23XQ(%5BS%24%2B!c%26AkICx%3D87%5B%40WY%3F*.(fKdd4Eo%5C%7D%26%2F%3C", false, -107), "1%23c%5Bmqvv5Q9TTgMlaqP)'%7Dk6Di%20%7C%2CMYz6%23X%7BlZSaM%2Fd%5D4g_07-o2MwUO%25IDCgLceK6%3A4rWpp%40Q%7Bh*2%3BH");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%24wa%5CLY.'%7BiBv%C2%A9%25~%C2%A9(%26%3Bd%25%5E4L%3FPsDPnO%09~%40%5BU~_6Qg.S2%7CZ%0ADY%0Aa%25%5Dq%3B%2Cr!Tz%0A%5B%22%0DL%C3%91R-%7C%C2%A9%25)v%26'X%5B%0D0Q%406fkv%C2%A922h%3F%7C%60%C3%91rZC)%2CTKnaTih%C2%A9%C2%A9Q", false, 222), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("t%3F%3AGe-%24%7Ck%40y*hq%5BtTH.%250%40b%2C%5Ds!s%3AjFdi%7D~%5CX%25zFMdaiy!d5u%26C%60%20EF%2F%2CQGOY%7CG1JvH94%3Eh0kkI%3Ep8Mkv%5E~Bx", true, -556), "%23MHUs%3B2%2ByN(8v%20i%23bV%3C3%3ENp%3Ak%22%2F%22HxTrw%2C-jf3)T%5Brow(%2FrC%244Qn.ST%3D%3A_U%5Dg%2BU%3FX%25VGBLv%3EyyWL~F%5By%25l-P'");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("a5%25%7D1%40%3EP2YyedWwRgA%3ELK%2Cb%23O4I%2BQ%2C%3C.%3Aox%60Cd.iw2E%3Cp%607aQ9yGApoxq%26g%5EXn%40%2Fy%3Ev%2B", true, -475), "a5%25%7D1%40%3EP2YyedWwRgA%3ELK%2Cb%23O4I%2BQ%2C%3C.%3Aox%60Cd.iw2E%3Cp%607aQ9yGApoxq%26g%5EXn%40%2Fy%3Ev%2B");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%22m%2B%3D8H%0D%C2%A9J5w%C3%91VB%20%C2%A9%C2%A9%7CWufZWk%C3%87%60K%C2%A9n%60%C2%A9%C3%87%5E%3F%C3%87xg*AAT%09", false, -515), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("5he%5Ea39%3Fzv%3DfB*%20%5Ce'ZDq!Yti%3A7a%3D1UHoS!aKF%7CacVkLAt%25ia%25%22!3onMGa%24tQRe6ae9'e%40%7D5WfVqiH'Dj~iWG1H54D%24y%7B", true, -89), "%3Bnkdg9%3FE!%7CClH0%26bk-%60Jw'_zo%40%3DgC7%5BNuY'gQL%23gi%5CqRGz%2Bog%2B('9utSMg*zWXk%3Cgk%3F-kF%24%3B%5Dl%5CwoN-Jp%25o%5DM7N%3B%3AJ*%20%22");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("T%26%5E%7CzahEWKu%7D%22y%3E%3B%60omkx%3Ab%22%3DF%408A%5D%20H%3B%3CV'K.xDDS%7DG%266%20%3FnD%2Byc%7Ds%26%25O%5B%2FW%2F%2C1%23r%7B.JHxhk_~8~a1z2PsQ", true, -749), "_1i(%26lsPbV!)-%25IFkzxv%24Em-HQKCLh%2BSFGa2V9%24OO%5E)R1A%2BJyO6%25n)~10Zf%3Ab%3A7%3C.%7D'9US%24svj*C*l%3C%26%3D%5B~%5C");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-%3B%24aiG%09n%0Am%C3%91X%3FAHq)%227P%0A%C2%A9gVM%C2%A9%23%2C0T%C3%91%C2%A92%0D_", true, -543), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("d%2B%5C%2B!G%25z8(R1%2FK0%24%22%5C%5B'YQGu%22Vx98%2FLmQS%20fHuB%23%25%22~k", true, 287), "f-%5E-%23I'%7C%3A*T31M2%26%24%5E%5D)%5BSIw%24Xz%3B%3A1NoSU%22hJwD%25'%24!m");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("q%22%3CYGsAoPHs%24t%60dU%3Fp02!DS%60xBe(L%40s%5DJq'BxwGK.4Wd%7C2%3Bvd%3EN%24K'3RybWU.", true, -9792), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("Gu%3CM2%7Dq(D%26v6%0AG8d(A%0Dnb1oRbSRC%3D%3C%40%20%C3%87r%23%26h_n%5CK-Ls%5D%60%40y54yaaP%0AlM)G%600TJ%C2%A9J%C2%A9Fq%7Cm%3E(F%3BQ", false, -461), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5CwZ!%2Few%23G%5D4HvWg5%24%2B%3Dhyx_'%2FSW%24Z%5EW%5DV%5DaJQ'R%2B%23%22Y'%3D96%2FY%209%3Cz_GOsX0l%26r%5B1%5Eh%7BPSj%7CpB%2Fd%20Y%5DW0k%2B%3DFo(*X", true, -10), "RmPv%25%5Bmx%3DS*%3ElM%5D%2By!3%5EonU%7C%25IMyPTMSLSW%40G%7CH!xwO%7C3%2F%2C%25Ou%2F2pU%3DEiN%26b%7BhQ'T%5EqFI%60rf8%25ZuOSM%26a!3%3Ce%7D%20N");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("K7B9*gn7%7Du%2B!rT%2BLj3sgC%22_b%2F3DQlk%3EW)v!iXO*H1%20MV%40ls%5B%3C%5BY%2Cy%23rjEM%2FR%5C%2F'%60N26%3B%25W1AqCG~dnS!er7*ZJ%5EVs8~_Ll%2Co%3F(T%5CN%24", false, 1057), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("c_Oz%3Fv!XG%3Ea9%3FPixUICU'6F5%3BnDoV%5Cd%5E)pvg19eNEf", true, 657), "%5BWGr7nxP%3F6Y17HapMA%3BM~.%3E-3f%3CgNT%5CV!hn_)1%5DF%3D%5E");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("d%0DV%2F%22C%2B1s%C3%87)ME.%20)X'%7D%C2%A9U%3F~q%0DrZ%3B%5C0jZb!nmT%2B%26zh0%0AH%3BFgAq%0DQ%23kC~%0DD(%3DTyz%3D%2F%7DKl1v%C2%A9VBRle%40E%C2%A9Ttj%2Fi%0D", true, -693), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%25E.%401Yfxz%3DABWe%25iN%3Cie(7AXd6gC%7D%3Ap5", true, 7747), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("g%5Eg%7Bw%26V%60OgVD%25F%5Ej%3Ef%3B%5CP4Wo%3D--TQC%60TUv)Nk.4_(%3CC2%25Dg%22qy.%5BO8XK", false, -7607), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("1%3AX%3EfyiGz%5Cr'j%5B1'Ie%7CUu%5Dm1%3Ap%23i2W%26.%7BU5%20Zk%5DCmA7%25gps%5Bt%26%3B_I%2CIvD.1)D%7D%3EB2)To*%5DRc_Mx5E2qXOLKxIX.)%3Av%5CUeJP", false, 4426), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%24G%3E7%25QE%7B)YMm~-%24%2BZcV%3EH%5B%20P70%5EDE%7C4UB%26%5B7%22r_HkI34rt7Wj*%60c2JKqQq%3A1qvewF%22%3Fgr%7D%400Yv%26%40i(Ij%22_uJeF%7C0%22kWB!I%3AdCXg%3A", true, 864), "-PG%40.ZN%252bVv(6-4cl_GQd)Y%409gMN%26%3D%5EK%2Fd%40%2B%7BhQtR%3C%3D%7B%7D%40%60s3il%3BSTzZzC%3Az%20n!O%2BHp%7B'I9b%20%2FIr1Rs%2Bh~SnO%269%2Bt%60K*RCmLapC");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput(".6S%5EXU%3CH%22%3BJ4I9h0%3An%5BN%40%25*P8(0%3CLc%3Cav64%3C%2F%5D%7C%23%3F%5EpgW.rK_m%24yQNBE9yqi)%7CyaE%5DZ%7CmJ3sc%3E~%2F2%24Fq%23'%3Dx%7C4y1Om%25o%3B%2B~Qd%24%5E~K%24i%26hB%3F%60r8%5B%2B..%5D%3F", false, 1005), "V%5E%7B'!%7DdpJcr%5Cqa1Xb7%24vhMRx%60PXdt%2Cd*%3F%5E%5CdW%26EKg'90%20V%3Bs(6LByvjmaB%3A2QEB*m%26%23E6r%5B%3C%2CfGWZLn%3AKOeAE%5CBYw6M8cSGy-L'GsL2N1jg)%3B%60%24SVV%26g");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%7Dfy%3D)%40%C3%91%C3%87(B%C3%87%09)%2C5t7%0D%40%C2%A9VI7w4%0A%40%5E*sB%60L0%C3%915J%5Dm%09%2BtD", false, -649), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("1C8%22hz-jK%5BQ%40%5E%20i%3AO%7D~r8gG%40sUg%20Ide9Q%7BKAjy5iv4%5Bqy%7DV-3JN%3D1K%5Di4)y%22LQ80%24%23O%23uyX.", true, -3250), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("yYHCAudJ6!w6%3A*%7D%5CR%2FtlEZ6o%3E0QbcIq2%5BTZCp_'!xmIDOolh'", true, 3544), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("LKFWkkqT%C3%87NF%09%0D6L%408%20SL%5Cx%0D%24ev%3E!NyF%3D%0DU%20U%5C%09%20%09%C2%A94m%3E_7%095cH%3D", false, -565), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("_xZwV%5C%40vIxK*jrJ'%3ALnN%22.%5E*I!%3FD%5C%3Et%2C%3A%20%5DN%40%7CQm%3A''br%60XX%3A%7BkYfkWKLk%20%26%5BmegIKG%7D7FutcHvr%24ZSTJk%22%7B%3D%5BmP1IC%246Uw3g%3Br6j7TL3J8Xu%3A*%20q%260.O%209%2F%23xLHHm", false, -950), "_xZwV%5C%40vIxK*jrJ'%3ALnN%22.%5E*I!%3FD%5C%3Et%2C%3A%20%5DN%40%7CQm%3A''br%60XX%3A%7BkYfkWKLk%20%26%5BmegIKG%7D7FutcHvr%24ZSTJk%22%7B%3D%5BmP1IC%246Uw3g%3Br6j7TL3J8Xu%3A*%20q%260.O%209%2F%23xLHHm");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%20Ee*u'7EF'%7DOzC%7B%3Bt%2F%25)pd%266u%60**DuW%2C%5E2%7B%5BjVCWQ%7C5QJOqFp%3B'%23%7C%25d%7Cc_'t%7D!M%60%7CaHYqA%2F%603%3Dy*%20%5Eo%7D2C%5C%60i%3AeR1dFj~bHnvWP%5B8%3CmOT9%5CE%5C-sbGrG%5Be7", false, 2211), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%0A(j%7De%0DSoTmz9%0DC%C2%A9%608bB%C3%91nBR%5Et%5Ek7%60q%3AH%C3%91'I%7C%C3%91r'B8B%2F%C3%87-h%0DFZ%23%26zbJ7n5%0Ao)JX%3A%C3%87EusSbI%7C", false, 955), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("~0RR7%5EhI%401%3AYByX2TepD%3FFz%24%5C!AH%2Fak%5E6%2B0Up%7C*NaS3PB!05U%2F!i)f%60D%3C%22QAnB%3DyL4!mp", true, -10103), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5EeAYa0Gs%5EuVD%5EwUq%3BXKjByu%40%5Cy%2266%24-mNr.bV(%3AtjNVjNxB%7Bira'k%3Dr%7B~%3A%20l~MX~s%5Cey%22N%3BW*fW%25fX2exS%7CtWC%5C%5B%23%3D8cR%257TB!r!LSz(26l%5D", true, 560), "T%5B7OW%26%3DiTkL%3ATmKg1NA%608ok6Row%2C%2Cy%23cDh%24XL%7D0j%60DL%60Dn8q_hW%7Ca3hqt0ubtCNtiR%5BowD1M%20%5CMz%5CN(%5BnIrjM9RQx3.YHz-J8vhvBIp%7D(%2CbS");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%22hvR9Oy%2Bh%40%60j%5CdGeK5a2%5EgP14%5DIk'xMXBiJq%3FqTaT%7BHVSUGL3%22j%3BOgte", true, 3925), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("7%3EgYD1%3AbaQ%3Ar%26C%2B%5C0%3D%60f%C2%A9~A%3F%265gn~%3E%3CQi%C3%91A%5BiV**%0AZ%C3%91%7BpA1%23%2FE%C3%87%20%40Y%C3%87H%2C)g%23nFCMis%09-IO%60%C3%91%7Ce%7C%60%2Cn%2Bv%40%09u'P%60%24%3Az89vx'%7B%3AmwnH2%3A", true, -474), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%24%3A%3EkUnmz1%3D9mITp%266AwLzsW%26~-!TFmXsh4%24P%5BWTj)Ww'jY_wm%5DS%3C%2CZb%22bN%5EXh%2F%3EC5kcY%25%2Cjq%3D9G2%7DD(%20pSXi%3FMiGNnC", false, -9264), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%40%3FXulz%2F%C2%A9%5Cp%20(%7CbXZ%C3%91s%0D-%2B83%2C%3F*%20w7mWhUWM_09J2%3F%3E0%3C%C2%A9Bb0CIeF%24bGni_%60f(%5CTk%3Fj%256%20iu6%20%3E7%3C%20M%3FVAba1Y%2F%26L4%3DWuq~%7Dt%09NIvwL%22%24%C2%A9dJ)22%C3%87mkU%7DR%2F7", true, -62), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2FR'2bhXC%5B%22%5D%5E%3DB8%2B%7BN2%5EI3%60x%3Da)Tc1%26%3FL%3Ctu6%5C8G%3Bph*4u%3Ab70%7Ba1%3Cn%3FcP%2BWs%3CE'kJ%24C%23%3AuG%23", true, 9544), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("99WFbX1d9%3FLPnT%5CN%23%7D%22%5CA%3Bwd%3CX)~H%7CH%7DXfK%25WF", true, 5228), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("C%09EBkT!%25%09%C2%A9ndNmjx%C2%A93%7CX%26%5EP%60%C3%91%5B%09kkmH%0DEy)O%0Aj%26JZEuhMyz%5D%2C%C3%87%C2%A91B%C3%87%C2%A9_kMpj", true, -274), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("eQnTp%3F%C2%A9%23%3E%C2%A9qCn%2B7bar%5C%09%7Cs)hLB%09%0DeJ%23cE3Z%3D.%C2%A9%0AD-jo%C3%87NE4%3Bkw%C3%912K7Bn%3C", true, 292), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C2%A9%5B%09Py~G'!U%0D%3D!Of7%5BS%C3%91wm%0A%2FcPYqimi%09%0De%C2%A9%C2%A9X%0D%C3%91%C3%87e%C2%A9%3CmI", false, -993), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("_rcC%26R8%3B%24~Pi3*%20o%3DdE%7D%3E0l5HxU%5B_BP(s%5Dk%5Dqj%7C~Fam~rM%3D)%40.wmQZDo%22%3FLO.%2F%5BD%2CAQcO%22AkVA*%25h%3B%3CHf6(cw%3BoP%2B%3BoO41UzGlH)%7D1'A5pdD%3CLnESP4Nsg%3CIov7%24NO%24", true, -656), "h%7BlL%2F%5BAD-(Yr%3C3)xFmN'G9u%3EQ%22%5EdhKY1%7Cftfzs%26(Ojv(%7BVF2I7!vZcMx%2BHUX78dM5JZlX%2BJt_J3.qDEQo%3F1l!DxY4DxX%3D%3A%5E%24PuQ2'%3A0J%3EymMEUwN%5CY%3DW%7CpERx%20%40-WX-");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%23%3Db%7C8mJy%09mAY%7C%0D%60%09zeh%09*%C3%91%25O%5E%0AX%22Q%C3%87p%C2%A9N%3C%0DM%0AjXWF%C3%87R%5BCo%09", true, -670), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("qk%3C%C2%A9)6%7Co%7C%C3%87iG%5Bhjz00*%C3%87l%23%23C%5E1iGe-d%0A%C2%A9%0AhPY3%24%3C3%23%097%23c_40n%40hEP*)ux%7Bs%2B%26%C3%91%C3%91", false, -371), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("nH%3ExSz%22p%3AP3%3C%20g%7COC(8YiKW9%23H%3AT%25U%3DLT!jmBQ%5BmQOHw%3F)-k%23k0%C3%87)f%246bfX%C3%91tHHF%3DK%7C1X'p9%23OY%3Dk", true, -406), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("U9O%5E5)54%40-7D-%60Z5MGf%60%23w%5BhEETk%2BH%7D)%23%40sU*f.t%40%5E9-*9%23O7vHWZk*mc-T0laQ%3Bb*cNMGX%5DD5ctwwdup%7D7!52Br", false, -162), "9%7C3Bxlxw%24pz(pD%3Ex1%2BJDf%5B%3FL))8On%2Calf%24W9mJqX%24B%7Cpm%7Cf3zZ%2C%3B%3EOmQGp8sPE5~FmG21%2B%3CA(xGX%5B%5BHYTazdxu%26V");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("NxF0084%249_nQuh%5C%5BOlw5%23Q%24E%3EC-AK7aKY12E%40%5D%7Cm80%3Aniw5r4%253%3B3B!Gj%23jSO5%2C(TJpRAXb%2BW3W8OQR%3A%20bV66%24g%26*!t", true, 9138), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("o.%22tVXAa7flj%3A~S%25UHDf%239_%3FS%23i3%60y-Ii%22.xFeF%3D%2CN7b-%60heW_mU)kP-'eEX(%22k0RvNO9Y%5C%5B%7B%22WXB(%5C%7Dr~(n_PGK'", false, 1060), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("L'L%40k%222%24Qw~UbxrF%25iPtEJE%3A%3A%23%24aRzC(!8TB%406'i)81%2BjbpyAb%3FzBBYKe", true, -3345), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("E%23~%5CK%3FZILZ%60aKZ~%23w%2F_)'1%3A%3Fxr-oU!0Nj%23(G.)!%2F*)Z%222%60%7BuAU240%5C_H-c%40Yx%5BGrL*_PO*)!Z%5D%5E%24KoMy%3A%5DO~%22bL)N*h%3DR7%7D6k%3AOa7%7CyerX%3DsD!'%3D%3FR*w%40%2B", false, -1121), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%5EOWLw%23L%5D!!9%3CIs!(bVt%24Aa2%26l%20lQsV5kmD%3APHEx%5C", false, 186), "bS%5BP%7B'Pa%25%25%3D%40Mw%25%2CfZx(Ee6*p%24pUwZ9oqH%3ETLI%7C%60");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("r.0(%7Czd%2CLa.T%20KFAA%22yaOA%2BYye8knbOQBPGl4xdQ%23aR%24zPdpE3k%5B", false, -7256), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%226*ots%5D%204%5E3TlEdu%60pxV%7D)83%5BU7Mv0*FUTp2sJB%23%3EU(!!7k9!%7CVpyjvu", false, 142), "RfZ%40ED.Pd%2Fc%25%3Du5F1AI'NYhc%2C%26g%7DG%60Zv%26%25AbDzrSn%26XQQg%3CiQM'AJ%3BGF");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%3Ap%5CS%7DxcfIbxFg-le%23tQU%5ED1%7B%23(w%2B%60%23h*lPY%2BI%40%60db%40R%20A1Kmg6EQqrckohB%40P%22-Pa%3B5R%25f%26DZ%3Fa%5BVYO", false, -374), "4jVMwr%5D%60C%5Cr%40a'f_%7CnKOX%3E%2Bu%7C%22q%25Z%7Cb%24fJS%25C%3AZ%5E%5C%3ALy%3B%2BEga0%3FKkl%5Deib%3C%3AJ%7B'J%5B5%2FL~%60%20%3ET9%5BUPSI");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("SE%24heS%26%7CA2Xo%5E4lj%20TX%60rd%7CunO0%3DIR31%5Bg%3B%7C%40pu%7BQ%2Cm3D1%3Av%3DUv%5BB%2Czo%26Dk%3F4*%26%5EwL)%2CH%5C_lz%7C%5DPV%2BEP%7BBqc0WMRMNd%5E%26)Eix%3D3UrXq%26m%236Ur%3D", true, -568), "UG%26jgU(~C4Zq%606nl%22VZbtf~wpQ2%3FKT53%5Di%3D~Brw%7DS.o5F3%3Cx%3FWx%5DD.%7Cq(FmA6%2C(%60yN%2B.J%5Ean%7C~_RX-GR%7DDse2YOTOPf%60(%2BGkz%3F5WtZs(o%258Wt%3F");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("cEl-7j%7CvweR4SDN%3Dm8F%7DQJfH1BHIM*Q'Z%7BX%60z65%3EnNyD%7CZ2F%5E.aJlw(.%22G3%7B~e%5CX%40%3C6_44%5B%5Dz%7Da%23B9zCiPglT%5B", true, 6965), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("6J%2C%3Fl6UTrUBk4XP%3CA%7C%60's%203%2C%7B%404%7Dq%3A)%3A%2F%3F%2C-l", false, 8195), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%20(7zc%5E%2FYArZ82%40c%2CjG%7D_IY*0-U-t3%5E7n0K9%3BGxPE2!W)jb_%24aW!uWM%25%7Bb!JfTR9geN%3AC%2CBI%3DA6%7BhGow%60SHG%3F%3F!%40_j%7Dr%5EdUD%5Dk", false, -4868), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%C2%A9%40!Qf%09v28%7BR%C3%87SVRY%C3%91%0D8%7D%3E(iD!fiLExC%C2%A9%C3%8757Jq%3C%5DI%09%0A%3Do!S%3B-Wz%0D%094O%09%C2%A9o!z%0A%7D47%C2%A9", false, -281), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("-DqRzU%0DF%7D5Bz5V%3A%3Cz*%0ATx1zqJ0%25e%7B)U%C2%A9-%7C%5ByQ%C3%91%2CMy%0D%0DY%5C%C2%A9IZ%2F%3F%2B*Lz%C3%87VN%24Z%0DF%3ExN%C3%87%25r%2C%26%C3%87BK-H", false, 254), null);
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("j3%3DL16oSTr%3BDu%3C%22J%3E%3B%7Bw%23%3DN%3DL%5EesdA9_PyCrJZ0%5Eyh%3Fe%2Bj1%3E%3C%5Ck%3DAl%22%3B%40j-%22%20%5Co_oxVq%2F~%60%406%3B7_RpgLT!NN)9s)j%3D1oOwp1%40tAsVdkL", true, 354), "Px%232v%7BU9%3AX!*%5B%22g0%24!a%5Dh%234%232DKYJ'~E6_)X0%40uD_N%25KpPv%24%22BQ%23'Rg!%26PrgeBUEU%5E%3CWtdF%26%7B!%7CE8VM2%3Af44n~YnP%23vU5%5DVv%26Z'Y%3CJQ2");
        EncryptTest.PRECOMPUTED_RESULTS
            .put(new EncryptInput("%2C0TC%25a_bIZ%245%24LKu1QffqpY%3AIYY%40okD3m)%5D'~%7Dk)%7Dat%5EEv%5C~j%24%402-c%5B%5Ed*%3Ei%20As%3F0mS%2B%5Bj19%5D%7Br%23%7D*WBfj%3Fl%2B%2B76PkXg%40%25T2Zb%5BD%3B%5D%3AJ%60kh%3Dd%26E", true, -2961), null);
        /* END AUTOGENERATED CODE */
    }
}
