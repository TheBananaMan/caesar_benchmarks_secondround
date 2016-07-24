#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto_aead.h"

#ifdef acorn128v2
#ifdef opt
#include "../crypto_aead/acorn128v2/opt/api.h"
#define FILENAME "log_acorn128v2_opt.txt"
#endif
#ifdef ref
#include "../crypto_aead/acorn128v2/ref/api.h"
#define FILENAME "log_acorn128v2_ref.txt"
#endif
#endif

#ifdef aeadaes128ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes128ocbtaglen128v1/opt/api.h"
#define FILENAME "log_aeadaes128ocbtaglen128v1_opt.txt"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen128v1/ref/api.h"
#define FILENAME "log_aeadaes128ocbtaglen128v1_ref.txt"
#endif
#endif

#ifdef aeadaes128ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen64v1/ref/api.h"
#define FILENAME "log_aeadaes128ocbtaglen64v1_ref.txt"
#endif
#endif

#ifdef aeadaes128ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen96v1/ref/api.h"
#define FILENAME "log_aeadaes128ocbtaglen96v1_ref.txt"
#endif
#endif

#ifdef aeadaes192ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes192ocbtaglen128v1/opt/api.h"
#define FILENAME "log_aeadaes192ocbtaglen128v1_opt.txt"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen128v1/ref/api.h"
#define FILENAME "log_aeadaes192ocbtaglen128v1_ref.txt"
#endif
#endif

#ifdef aeadaes192ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen64v1/ref/api.h"
#define FILENAME "log_aeadaes192ocbtaglen64v1_ref.txt"
#endif
#endif

#ifdef aeadaes192ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen96v1/ref/api.h"
#define FILENAME "log_aeadaes192ocbtaglen96v1_ref.txt"
#endif
#endif

#ifdef aeadaes256ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes256ocbtaglen128v1/opt/api.h"
#define FILENAME "log_aeadaes256ocbtaglen128v1_opt.txt"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen128v1/ref/api.h"
#define FILENAME "log_aeadaes256ocbtaglen128v1_ref.txt"
#endif
#endif

#ifdef aeadaes256ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen64v1/ref/api.h"
#define FILENAME "log_aeadaes256ocbtaglen64v1_ref.txt"
#endif
#endif

#ifdef aeadaes256ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen96v1/ref/api.h"
#define FILENAME "log_aeadaes256ocbtaglen96v1_ref.txt"
#endif
#endif

#ifdef aegis128
#ifdef aesni
#include "../crypto_aead/aegis128/aesni/api.h"
#define FILENAME "log_aegis128_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aegis128/ref/api.h"
#define FILENAME "log_aegis128_ref.txt"
#endif
#endif

#ifdef aegis128l
#ifdef aesnia
#include "../crypto_aead/aegis128l/aesnia/api.h"
#define FILENAME "log_aegis128l_aesnia.txt"
#endif
#ifdef aesnib
#include "../crypto_aead/aegis128l/aesnib/api.h"
#define FILENAME "log_aegis128l_aesnib.txt"
#endif
#ifdef aesnic
#include "../crypto_aead/aegis128l/aesnic/api.h"
#define FILENAME "log_aegis128l_aesnic.txt"
#endif
#ifdef ref
#include "../crypto_aead/aegis128l/ref/api.h"
#define FILENAME "log_aegis128l_ref.txt"
#endif
#endif

#ifdef aegis256
#ifdef aesni
#include "../crypto_aead/aegis256/aesni/api.h"
#define FILENAME "log_aegis256_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aegis256/ref/api.h"
#define FILENAME "log_aegis256_ref.txt"
#endif
#endif

#ifdef aes128gcmv1
#ifdef openssl
#include "../crypto_aead/aes128gcmv1/openssl/api.h"
#define FILENAME "log_aes128gcmv1_openssl.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128gcmv1/ref/api.h"
#define FILENAME "log_aes128gcmv1_ref.txt"
#endif
#endif

#ifdef aes128n12t8clocv2
#ifdef aesni
#include "../crypto_aead/aes128n12t8clocv2/aesni/api.h"
#define FILENAME "log_aes128n12t8clocv2_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128n12t8clocv2/ref/api.h"
#define FILENAME "log_aes128n12t8clocv2_ref.txt"
#endif
#endif

#ifdef aes128n12t8silcv2
#ifdef aesni
#include "../crypto_aead/aes128n12t8silcv2/aesni/api.h"
#define FILENAME "log_aes128n12t8silcv2_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128n12t8silcv2/ref/api.h"
#define FILENAME "log_aes128n12t8silcv2_ref.txt"
#endif
#endif

#ifdef aes128n8t8clocv2
#ifdef aesni
#include "../crypto_aead/aes128n8t8clocv2/aesni/api.h"
#define FILENAME "log_aes128n8t8clocv2_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128n8t8clocv2/ref/api.h"
#define FILENAME "log_aes128n8t8clocv2_ref.txt"
#endif
#endif

#ifdef aes128n8t8silcv2
#ifdef aesni
#include "../crypto_aead/aes128n8t8silcv2/aesni/api.h"
#define FILENAME "log_aes128n8t8silcv2_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128n8t8silcv2/ref/api.h"
#define FILENAME "log_aes128n8t8silcv2_ref.txt"
#endif
#endif

#ifdef aes128otrpv2
#ifdef ref
#include "../crypto_aead/aes128otrpv2/ref/api.h"
#define FILENAME "log_aes128otrpv2_ref.txt"
#endif
#endif

#ifdef aes128otrpv3
#ifdef ref
#include "../crypto_aead/aes128otrpv3/ref/api.h"
#define FILENAME "log_aes128otrpv3_ref.txt"
#endif
#ifdef nip7m1
#include "../crypto_aead/aes128otrpv3/nip7m1/api.h"
#define FILENAME "log_aes128otrpv3_nip7m1.txt"
#endif
#ifdef nip7m2
#include "../crypto_aead/aes128otrpv3/nip7m2/api.h"
#define FILENAME "log_aes128otrpv3_nip7m2.txt"
#endif
#ifdef nip8m1
#include "../crypto_aead/aes128otrpv3/nip8m1/api.h"
#define FILENAME "log_aes128otrpv3_nip8m1.txt"
#endif
#ifdef nip8m2
#include "../crypto_aead/aes128otrpv3/nip8m2/api.h"
#define FILENAME "log_aes128otrpv3_nip8m2.txt"
#endif
#endif

#ifdef aes128otrsv2
#ifdef ref
#include "../crypto_aead/aes128otrsv2/ref/api.h"
#define FILENAME "log_aes128otrsv2_ref.txt"
#endif
#endif

#ifdef aes128otrsv3
#ifdef ref
#include "../crypto_aead/aes128otrsv3/ref/api.h"
#define FILENAME "log_aes128otrsv3_ref.txt"
#endif
#ifdef nip7m1
#include "../crypto_aead/aes128otrsv3/nip7m1/api.h"
#define FILENAME "log_aes128otrsv3_nip7m1.txt"
#endif
#ifdef nip7m2
#include "../crypto_aead/aes128otrsv3/nip7m2/api.h"
#define FILENAME "log_aes128otrsv3_nip7m2.txt"
#endif
#ifdef nip8m1
#include "../crypto_aead/aes128otrsv3/nip8m1/api.h"
#define FILENAME "log_aes128otrsv3_nip8m1.txt"
#endif
#ifdef nip8m2
#include "../crypto_aead/aes128otrsv3/nip8m2/api.h"
#define FILENAME "log_aes128otrsv3_nip8m2.txt"
#endif
#endif

#ifdef aes128poetv2aes128ls0lt0
#ifdef ni
#include "../crypto_aead/aes128poetv2aes128ls0lt0/ni/api.h"
#define FILENAME "log_aes128poetv2aes128ls0lt0_ni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128poetv2aes128ls0lt0/ref/api.h"
#define FILENAME "log_aes128poetv2aes128ls0lt0_ref.txt"
#endif
#endif

#ifdef aes128poetv2aes128ls128lt128
#ifdef ref
#include "../crypto_aead/aes128poetv2aes128ls128lt128/ref/api.h"
#define FILENAME "log_aes128poetv2aes128ls128lt128_ref.txt"
#endif
#endif

#ifdef aes128poetv2aes4ls0lt0
#ifdef ni
#include "../crypto_aead/aes128poetv2aes4ls0lt0/ni/api.h"
#define FILENAME "log_aes128poetv2aes4ls0lt0_ni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes128poetv2aes4ls0lt0/ref/api.h"
#define FILENAME "log_aes128poetv2aes4ls0lt0_ref.txt"
#endif
#endif

#ifdef aes128poetv2aes4ls128lt128
#ifdef ref
#include "../crypto_aead/aes128poetv2aes4ls128lt128/ref/api.h"
#define FILENAME "log_aes128poetv2aes4ls128lt128_ref.txt"
#endif
#endif

#ifdef aes256gcmv1
#ifdef cryptopp
#include "../crypto_aead/aes256gcmv1/cryptopp/api.h"
#define FILENAME "log_aes256gcmv1_cryptopp.txt"
#endif
#ifdef openssl
#include "../crypto_aead/aes256gcmv1/openssl/api.h"
#define FILENAME "log_aes256gcmv1_openssl.txt"
#endif
#ifdef ref
#include "../crypto_aead/aes256gcmv1/ref/api.h"
#define FILENAME "log_aes256gcmv1_ref.txt"
#endif
#endif

#ifdef aes256otrpv2
#ifdef ref
#include "../crypto_aead/aes256otrpv2/ref/api.h"
#define FILENAME "log_aes256otrpv2_ref.txt"
#endif
#endif

#ifdef aes256otrpv3
#ifdef ref
#include "../crypto_aead/aes256otrpv3/ref/api.h"
#define FILENAME "log_aes256otrpv3_ref.txt"
#endif
#ifdef nip7m1
#include "../crypto_aead/aes256otrpv3/nip7m1/api.h"
#define FILENAME "log_aes256otrpv3_nip7m1.txt"
#endif
#ifdef nip7m2
#include "../crypto_aead/aes256otrpv3/nip7m2/api.h"
#define FILENAME "log_aes128otrpv3_nip7m2.txt"
#endif
#ifdef nip8m1
#include "../crypto_aead/aes256otrpv3/nip8m1/api.h"
#define FILENAME "log_aes256otrpv3_nip8m1.txt"
#endif
#ifdef nip8m2
#include "../crypto_aead/aes256otrpv3/nip8m2/api.h"
#define FILENAME "log_aes256otrpv3_nip8m2.txt"
#endif
#endif

#ifdef aes256otrsv2
#ifdef ref
#include "../crypto_aead/aes256otrsv2/ref/api.h"
#define FILENAME "log_aes256otrsv2_ref.txt"
#endif
#endif

#ifdef aes256otrsv3
#ifdef ref
#include "../crypto_aead/aes256otrsv3/ref/api.h"
#define FILENAME "log_aes256otrsv3_ref.txt"
#endif
#ifdef nip7m1
#include "../crypto_aead/aes256otrsv3/nip7m1/api.h"
#define FILENAME "log_aes256otrsv3_nip7m1.txt"
#endif
#ifdef nip7m2
#include "../crypto_aead/aes256otrsv3/nip7m2/api.h"
#define FILENAME "log_aes256otrsv3_nip7m2.txt"
#endif
#ifdef nip8m1
#include "../crypto_aead/aes256otrsv3/nip8m1/api.h"
#define FILENAME "log_aes256otrsv3_nip8m1.txt"
#endif
#ifdef nip8m2
#include "../crypto_aead/aes256otrsv3/nip8m2/api.h"
#define FILENAME "log_aes256otrsv3_nip8m2.txt"
#endif
#endif

#ifdef aescopav2
#ifdef ref
#include "../crypto_aead/aescopav2/ref/api.h"
#define FILENAME "log_aescopav2_ref.txt"
#endif
#endif

#ifdef aesjambuv2
#ifdef aesni
#include "../crypto_aead/aesjambuv2/aesni/api.h"
#define FILENAME "log_aesjambuv2_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aesjambuv2/ref/api.h"
#define FILENAME "log_aesjambuv2_ref.txt"
#endif
#endif

#ifdef aezv4
#ifdef aesni
#include "../crypto_aead/aezv4/aesni/api.h"
#define FILENAME "log_aezv4_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/aezv4/ref/api.h"
#define FILENAME "log_aezv4_ref.txt"
#endif
#endif

#ifdef ascon128av11
#ifdef opt64
#include "../crypto_aead/ascon128av11/opt64/api.h"
#define FILENAME "log_ascon128av11_opt64.txt"
#endif
#ifdef ref
#include "../crypto_aead/ascon128av11/ref/api.h"
#define FILENAME "log_ascon128av11_ref.txt"
#endif
#endif

#ifdef ascon128v11
#ifdef opt64
#include "../crypto_aead/ascon128v11/opt64/api.h"
#define FILENAME "log_ascon128v11_opt64.txt"
#endif
#ifdef ref
#include "../crypto_aead/ascon128v11/ref/api.h"
#define FILENAME "log_ascon128v11_ref.txt"
#endif
#endif

#ifdef deoxyseq128128v13
#ifdef ref
#include "../crypto_aead/deoxyseq128128v13/ref/api.h"
#define FILENAME "log_deoxyseq128128v13_ref.txt"
#endif
#endif

#ifdef deoxyseq256128v13
#ifdef ref
#include "../crypto_aead/deoxyseq256128v13/ref/api.h"
#define FILENAME "log_deoxyseq256128v13_ref.txt"
#endif
#endif

#ifdef deoxysneq128128v13
#ifdef aesni
#include "../crypto_aead/deoxysneq128128v13/aesni/api.h"
#define FILENAME "log_deoxysneq128128v13_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/deoxysneq128128v13/ref/api.h"
#define FILENAME "log_deoxysneq128128v13_ref.txt"
#endif
#endif

#ifdef deoxysneq256128v13
#ifdef aesni
#include "../crypto_aead/deoxysneq256128v13/aesni/api.h"
#define FILENAME "log_deoxysneq256128v13_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/deoxysneq256128v13/ref/api.h"
#define FILENAME "log_deoxysneq256128v13_ref.txt"
#endif
#endif

#ifdef elmd1000v2
#ifdef ref
#include "../crypto_aead/elmd1000v2/ref/api.h"
#define FILENAME "log_elmd1000v2_ref.txt"
#endif
#endif

#ifdef elmd1001v2
#ifdef ref
#include "../crypto_aead/elmd1001v2/ref/api.h"
#define FILENAME "log_elmd1001v2_ref.txt"
#endif
#endif

#ifdef elmd101270v2
#ifdef ref
#include "../crypto_aead/elmd101270v2/ref/api.h"
#define FILENAME "log_elmd101270v2_ref.txt"
#endif
#endif

#ifdef elmd101271v2
#ifdef ref
#include "../crypto_aead/elmd101271v2/ref/api.h"
#define FILENAME "log_elmd101271v2_ref.txt"
#endif
#endif

#ifdef elmd600v2
#ifdef ref
#include "../crypto_aead/elmd600v2/ref/api.h"
#define FILENAME "log_elmd600v2_ref.txt"
#endif
#endif

#ifdef elmd601v2
#ifdef ref
#include "../crypto_aead/elmd601v2/ref/api.h"
#define FILENAME "log_elmd601v2_ref.txt"
#endif
#endif

#ifdef elmd61270v2
#ifdef ref
#include "../crypto_aead/elmd61270v2/ref/api.h"
#define FILENAME "log_elmd61270v2_ref.txt"
#endif
#endif

#ifdef elmd61271v2
#ifdef ref
#include "../crypto_aead/elmd61271v2/ref/api.h"
#define FILENAME "log_elmd61271v2_ref.txt"
#endif
#endif

#ifdef hs1sivhiv1
#ifdef ref
#include "../crypto_aead/hs1sivhiv1/ref/api.h"
#define FILENAME "log_hs1sivhiv1_ref.txt"
#endif
#endif

#ifdef hs1sivlov1
#ifdef ref
#include "../crypto_aead/hs1sivlov1/ref/api.h"
#define FILENAME "log_hs1sivlov1_ref.txt"
#endif
#endif

#ifdef hs1sivv1
#ifdef ref
#include "../crypto_aead/hs1sivv1/ref/api.h"
#define FILENAME "log_hs1sivv1_ref.txt"
#endif
#endif

#ifdef icepole128av2
#ifdef ref
#include "../crypto_aead/icepole128av2/ref/api.h"
#define FILENAME "log_icepole128av2_ref.txt"
#endif
#endif

#ifdef icepole128v2
#ifdef ref
#include "../crypto_aead/icepole128v2/ref/api.h"
#define FILENAME "log_icepole128v2_ref.txt"
#endif
#endif

#ifdef icepole256av2
#ifdef ref
#include "../crypto_aead/icepole256av2/ref/api.h"
#define FILENAME "log_icepole256av2_ref.txt"
#endif
#endif

#ifdef joltikeq12864v13
#ifdef ref
#include "../crypto_aead/joltikeq12864v13/ref/api.h"
#define FILENAME "log_joltikeq12864v13_ref.txt"
#endif
#endif

#ifdef joltikeq6464v13
#ifdef ref
#include "../crypto_aead/joltikeq6464v13/ref/api.h"
#define FILENAME "log_joltikeq6464v13_ref.txt"
#endif
#endif

#ifdef joltikeq80112v13
#ifdef ref
#include "../crypto_aead/joltikeq80112v13/ref/api.h"
#define FILENAME "log_joltikeq80112v13_ref.txt"
#endif
#endif

#ifdef joltikeq9696v13
#ifdef ref
#include "../crypto_aead/joltikeq9696v13/ref/api.h"
#define FILENAME "log_joltikeq9696v13_ref.txt"
#endif
#endif

#ifdef joltikneq12864v13
#ifdef ref
#include "../crypto_aead/joltikneq12864v13/ref/api.h"
#define FILENAME "log_joltikneq12864v13_ref.txt"
#endif
#endif

#ifdef joltikneq6464v13
#ifdef ref
#include "../crypto_aead/joltikneq6464v13/ref/api.h"
#define FILENAME "log_joltikneq6464v13_ref.txt"
#endif
#endif

#ifdef joltikneq80112v13
#ifdef ref
#include "../crypto_aead/joltikneq80112v13/ref/api.h"
#define FILENAME "log_joltikneq80112v13_ref.txt"
#endif
#endif

#ifdef joltikneq9696v13
#ifdef ref
#include "../crypto_aead/joltikneq9696v13/ref/api.h"
#define FILENAME "log_joltikneq9696v13_ref.txt"
#endif
#endif

#ifdef ketjejrv1
#ifdef ARMv6M
#include "../crypto_aead/ketjejrv1/ARMv6M/api.h"
#define FILENAME "log_ketjejrv1_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/ketjejrv1/ARMv7M/api.h"
#define FILENAME "log_ketjejrv1_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/ketjejrv1/AVR8/api.h"
#define FILENAME "log_ketjejrv1_AVR8.txt"
#endif
#ifdef compact
#include "../crypto_aead/ketjejrv1/compact/api.h"
#define FILENAME "log_ketjejrv1_compact.txt"
#endif
#ifdef reference
#include "../crypto_aead/ketjejrv1/reference/api.h"
#define FILENAME "log_ketjejrv1_reference.txt"
#endif
#endif

#ifdef ketjesrv1
#ifdef ARMv6M
#include "../crypto_aead/ketjesrv1/ARMv6M/api.h"
#define FILENAME "log_ketjesrv1_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/ketjesrv1/ARMv7M/api.h"
#define FILENAME "log_ketjesrv1_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/ketjesrv1/AVR8/api.h"
#define FILENAME "log_ketjesrv1_AVR8.txt"
#endif
#ifdef compact
#include "../crypto_aead/ketjesrv1/compact/api.h"
#define FILENAME "log_ketjesrv1_compact.txt"
#endif
#ifdef reference
#include "../crypto_aead/ketjesrv1/reference/api.h"
#define FILENAME "log_ketjesrv1_reference.txt"
#endif
#endif

#ifdef lakekeyakv2
#ifdef ARMv6M
#include "../crypto_aead/lakekeyakv2/ARMv6M/api.h"
#define FILENAME "log_lakekeyakv2_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/lakekeyakv2/ARMv7M/api.h"
#define FILENAME "log_lakekeyakv2_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/lakekeyakv2/AVR8/api.h"
#define FILENAME "log_lakekeyakv2_AVR8.txt"
#endif
#ifdef Bulldozer
#include "../crypto_aead/lakekeyakv2/Bulldozer/api.h"
#define FILENAME "log_lakekeyakv2_Bulldozer.txt"
#endif
#ifdef Haswell
#include "../crypto_aead/lakekeyakv2/Haswell/api.h"
#define FILENAME "log_lakekeyakv2_Haswell.txt"
#endif
#ifdef Nehalem
#include "../crypto_aead/lakekeyakv2/Nehalem/api.h"
#define FILENAME "log_lakekeyakv2_Nehalem.txt"
#endif
#ifdef SandyBridge
#include "../crypto_aead/lakekeyakv2/SandyBridge/api.h"
#define FILENAME "log_lakekeyakv2_SandyBridge.txt"
#endif
#ifdef asmX8664
#include "../crypto_aead/lakekeyakv2/asmX8664/api.h"
#define FILENAME "log_lakekeyakv2_asmX8664.txt"
#endif
#ifdef asmX8664shld
#include "../crypto_aead/lakekeyakv2/asmX8664shld/api.h"
#define FILENAME "log_lakekeyakv2_asmX8664shld.txt"
#endif
#ifdef compact
#include "../crypto_aead/lakekeyakv2/compact/api.h"
#define FILENAME "log_lakekeyakv2_compact.txt"
#endif
#ifdef generic32
#include "../crypto_aead/lakekeyakv2/generic32/api.h"
#define FILENAME "log_lakekeyakv2_generic32.txt"
#endif
#ifdef generic32lc
#include "../crypto_aead/lakekeyakv2/generic32lc/api.h"
#define FILENAME "log_lakekeyakv2_generic32lc.txt"
#endif
#ifdef generic64
#include "../crypto_aead/lakekeyakv2/generic64/api.h"
#define FILENAME "log_lakekeyakv2_generic64.txt"
#endif
#ifdef generic64lc
#include "../crypto_aead/lakekeyakv2/generic64lc/api.h"
#define FILENAME "log_lakekeyakv2_generic64lc.txt"
#endif
#ifdef reference32bits
#include "../crypto_aead/lakekeyakv2/reference32bits/api.h"
#define FILENAME "log_lakekeyakv2_reference32bits.txt"
#endif
#endif

#ifdef led80n6t4silcv2
#ifdef ref
#include "../crypto_aead/led80n6t4silcv2/ref/api.h"
#define FILENAME "log_led80n6t4silcv2_ref.txt"
#endif
#endif

#ifdef lunarkeyakv2
#ifdef ARMv6M
#include "../crypto_aead/lunarkeyakv2/ARMv6M/api.h"
#define FILENAME "log_lunarkeyakv2_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/lunarkeyakv2/ARMv7M/api.h"
#define FILENAME "log_lunarkeyakv2_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/lunarkeyakv2/AVR8/api.h"
#define FILENAME "log_lunarkeyakv2_AVR8.txt"
#endif
#ifdef Bulldozer
#include "../crypto_aead/lunarkeyakv2/Bulldozer/api.h"
#define FILENAME "log_lunarkeyakv2_Bulldozer.txt"
#endif
#ifdef Haswell
#include "../crypto_aead/lunarkeyakv2/Haswell/api.h"
#define FILENAME "log_lunarkeyakv2_Haswell.txt"
#endif
#ifdef Nehalem
#include "../crypto_aead/lunarkeyakv2/Nehalem/api.h"
#define FILENAME "log_lunarkeyakv2_Nehalem.txt"
#endif
#ifdef SandyBridge
#include "../crypto_aead/lunarkeyakv2/SandyBridge/api.h"
#define FILENAME "log_lunarkeyakv2_SandyBridge.txt"
#endif
#ifdef asmX8664
#include "../crypto_aead/lunarkeyakv2/asmX8664/api.h"
#define FILENAME "log_lunarkeyakv2_asmX8664.txt"
#endif
#ifdef asmX8664shld
#include "../crypto_aead/lunarkeyakv2/asmX8664shld/api.h"
#define FILENAME "log_lunarkeyakv2_asmX8664shld.txt"
#endif
#ifdef compact
#include "../crypto_aead/lunarkeyakv2/compact/api.h"
#define FILENAME "log_lunarkeyakv2_compact.txt"
#endif
#ifdef generic32
#include "../crypto_aead/lunarkeyakv2/generic32/api.h"
#define FILENAME "log_lunarkeyakv2_generic32.txt"
#endif
#ifdef generic32lc
#include "../crypto_aead/lunarkeyakv2/generic32lc/api.h"
#define FILENAME "log_lunarkeyakv2_generic32lc.txt"
#endif
#ifdef generic64
#include "../crypto_aead/lunarkeyakv2/generic64/api.h"
#define FILENAME "log_lunarkeyakv2_generic64.txt"
#endif
#ifdef generic64lc
#include "../crypto_aead/lunarkeyakv2/generic64lc/api.h"
#define FILENAME "log_lunarkeyakv2_generic64lc.txt"
#endif
#ifdef reference32bits
#include "../crypto_aead/lunarkeyakv2/reference32bits/api.h"
#define FILENAME "log_lunarkeyakv2_reference32bits.txt"
#endif
#endif

#ifdef minalpherv11
#ifdef avx2
#include "../crypto_aead/minalpherv11/avx2/api.h"
#define FILENAME "log_minalpherv11_avx2.txt"
#endif
#ifdef ref
#include "../crypto_aead/minalpherv11/ref/api.h"
#define FILENAME "log_minalpherv11_ref.txt"
#endif
#endif

#ifdef morus1280128v1
#ifdef avx2
#include "../crypto_aead/morus1280128v1/avx2/api.h"
#define FILENAME "log_morus1280128v1_avx2.txt"
#endif
#ifdef ref
#include "../crypto_aead/morus1280128v1/ref/api.h"
#define FILENAME "log_morus1280128v1_ref.txt"
#endif
#ifdef ref64
#include "../crypto_aead/morus1280128v1/ref64/api.h"
#define FILENAME "log_morus1280128v1_ref64.txt"
#endif
#ifdef sse2
#include "../crypto_aead/morus1280128v1/sse2/api.h"
#define FILENAME "log_morus1280128v1_sse2.txt"
#endif
#endif

#ifdef morus1280256v1
#ifdef avx2
#include "../crypto_aead/morus1280256v1/avx2/api.h"
#define FILENAME "log_morus1280256v1_avx2.txt"
#endif
#ifdef ref
#include "../crypto_aead/morus1280256v1/ref/api.h"
#define FILENAME "log_morus1280256v1_ref.txt"
#endif
#ifdef ref64
#include "../crypto_aead/morus1280256v1/ref64/api.h"
#define FILENAME "log_morus1280256v1_ref64.txt"
#endif
#ifdef sse2
#include "../crypto_aead/morus1280256v1/sse2/api.h"
#define FILENAME "log_morus1280256v1_sse2.txt"
#endif
#endif

#ifdef morus640128v1
#ifdef ref
#include "../crypto_aead/morus640128v1/ref/api.h"
#define FILENAME "log_morus640128v1_ref.txt"
#endif
#ifdef sse2
#include "../crypto_aead/morus640128v1/sse2/api.h"
#define FILENAME "log_morus640128v1_sse2.txt"
#endif
#endif

#ifdef norx0841
#ifdef ref
#include "../crypto_aead/norx0841/ref/api.h"
#define FILENAME "log_norx0841_ref.txt"
#endif
#endif

#ifdef norx1641
#ifdef ref
#include "../crypto_aead/norx1641/ref/api.h"
#define FILENAME "log_norx1641_ref.txt"
#endif
#endif

#ifdef norx3241
#ifdef neon
#include "../crypto_aead/norx3241/neon/api.h"
#define FILENAME "log_norx3241_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/norx3241/ref/api.h"
#define FILENAME "log_norx3241_ref.txt"
#endif
#ifdef xmm
#include "../crypto_aead/norx3241/xmm/api.h"
#define FILENAME "log_norx3241_xmm.txt"
#endif
#endif

#ifdef norx3261
#ifdef neon
#include "../crypto_aead/norx3261/neon/api.h"
#define FILENAME "log_norx3261_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/norx3261/ref/api.h"
#define FILENAME "log_norx3261_ref.txt"
#endif
#ifdef xmm
#include "../crypto_aead/norx3261/xmm/api.h"
#define FILENAME "log_norx3261_xmm.txt"
#endif
#endif

#ifdef norx6441
#ifdef neon
#include "../crypto_aead/norx6441/neon/api.h"
#define FILENAME "log_norx6441_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/norx6441/ref/api.h"
#define FILENAME "log_norx6441_ref.txt"
#endif
#ifdef xmm
#include "../crypto_aead/norx6441/xmm/api.h"
#define FILENAME "log_norx6441_xmm.txt"
#endif
#ifdef ymm
#include "../crypto_aead/norx6441/ymm/api.h"
#define FILENAME "log_norx6441_ymm.txt"
#endif
#endif

#ifdef norx6444
#ifdef ref
#include "../crypto_aead/norx6444/ref/api.h"
#define FILENAME "log_norx6444_ref.txt"
#endif
#endif

#ifdef norx6461
#ifdef neon
#include "../crypto_aead/norx6461/neon/api.h"
#define FILENAME "log_norx6461_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/norx6461/ref/api.h"
#define FILENAME "log_norx6461_ref.txt"
#endif
#ifdef xmm
#include "../crypto_aead/norx6461/xmm/api.h"
#define FILENAME "log_norx6461_xmm.txt"
#endif
#ifdef ymm
#include "../crypto_aead/norx6461/ymm/api.h"
#define FILENAME "log_norx6461_ymm.txt"
#endif
#endif

#ifdef oceankeyakv2
#ifdef ARMv6M
#include "../crypto_aead/oceankeyakv2/ARMv6M/api.h"
#define FILENAME "log_oceankeyakv2_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/oceankeyakv2/ARMv7M/api.h"
#define FILENAME "log_oceankeyakv2_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/oceankeyakv2/AVR8/api.h"
#define FILENAME "log_oceankeyakv2_AVR8.txt"
#endif
#ifdef Bulldozer
#include "../crypto_aead/oceankeyakv2/Bulldozer/api.h"
#define FILENAME "log_oceankeyakv2_Bulldozer.txt"
#endif
#ifdef Haswell
#include "../crypto_aead/oceankeyakv2/Haswell/api.h"
#define FILENAME "log_oceankeyakv2_Haswell.txt"
#endif
#ifdef Nehalem
#include "../crypto_aead/oceankeyakv2/Nehalem/api.h"
#define FILENAME "log_oceankeyakv2_Nehalem.txt"
#endif
#ifdef SandyBridge
#include "../crypto_aead/oceankeyakv2/SandyBridge/api.h"
#define FILENAME "log_oceankeyakv2_SandyBridge.txt"
#endif
#ifdef asmX8664
#include "../crypto_aead/oceankeyakv2/asmX8664/api.h"
#define FILENAME "log_oceankeyakv2_asmX8664.txt"
#endif
#ifdef asmX8664shld
#include "../crypto_aead/oceankeyakv2/asmX8664shld/api.h"
#define FILENAME "log_oceankeyakv2_asmX8664shld.txt"
#endif
#ifdef compact
#include "../crypto_aead/oceankeyakv2/compact/api.h"
#define FILENAME "log_oceankeyakv2_compact.txt"
#endif
#ifdef generic32
#include "../crypto_aead/oceankeyakv2/generic32/api.h"
#define FILENAME "log_oceankeyakv2_generic32.txt"
#endif
#ifdef generic32lc
#include "../crypto_aead/oceankeyakv2/generic32lc/api.h"
#define FILENAME "log_oceankeyakv2_generic32lc.txt"
#endif
#ifdef generic64
#include "../crypto_aead/oceankeyakv2/generic64/api.h"
#define FILENAME "log_oceankeyakv2_generic64.txt"
#endif
#ifdef generic64lc
#include "../crypto_aead/oceankeyakv2/generic64lc/api.h"
#define FILENAME "log_oceankeyakv2_generic64lc.txt"
#endif
#ifdef reference32bits
#include "../crypto_aead/oceankeyakv2/reference32bits/api.h"
#define FILENAME "log_oceankeyakv2_reference32bits.txt"
#endif
#endif

#ifdef omdsha256k128n96tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau128v2/avx1/api.h"
#define FILENAME "log_omdsha256k128n96tau128v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau128v2/ref/api.h"
#define FILENAME "log_omdsha256k128n96tau128v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau128v2/sse4/api.h"
#define FILENAME "log_omdsha256k128n96tau128v2_sse4.txt"
#endif
#endif

#ifdef omdsha256k128n96tau64v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau64v2/avx1/api.h"
#define FILENAME "log_omdsha256k128n96tau64v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau64v2/ref/api.h"
#define FILENAME "log_omdsha256k128n96tau64v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau64v2/sse4/api.h"
#define FILENAME "log_omdsha256k128n96tau64v2_sse4.txt"
#endif
#endif

#ifdef omdsha256k128n96tau96v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau96v2/avx1/api.h"
#define FILENAME "log_omdsha256k128n96tau96v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau96v2/ref/api.h"
#define FILENAME "log_omdsha256k128n96tau96v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau96v2/sse4/api.h"
#define FILENAME "log_omdsha256k128n96tau96v2_sse4.txt"
#endif
#endif

#ifdef omdsha256k192n104tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha256k192n104tau128v2/avx1/api.h"
#define FILENAME "log_omdsha256k192n104tau128v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k192n104tau128v2/ref/api.h"
#define FILENAME "log_omdsha256k192n104tau128v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k192n104tau128v2/sse4/api.h"
#define FILENAME "log_omdsha256k192n104tau128v2_sse4.txt"
#endif
#endif

#ifdef omdsha256k256n104tau160v2
#ifdef avx1
#include "../crypto_aead/omdsha256k256n104tau160v2/avx1/api.h"
#define FILENAME "log_omdsha256k256n104tau160v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k256n104tau160v2/ref/api.h"
#define FILENAME "log_omdsha256k256n104tau160v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k256n104tau160v2/sse4/api.h"
#define FILENAME "log_omdsha256k256n104tau160v2_sse4.txt"
#endif
#endif

#ifdef omdsha256k256n248tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha256k256n248tau256v2/avx1/api.h"
#define FILENAME "log_omdsha256k256n248tau256v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k256n248tau256v2/ref/api.h"
#define FILENAME "log_omdsha256k256n248tau256v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k256n248tau256v2/sse4/api.h"
#define FILENAME "log_omdsha256k256n248tau256v2_sse4.txt"
#endif
#endif

#ifdef omdsha512k128n128tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha512k128n128tau128v2/avx1/api.h"
#define FILENAME "log_omdsha512k128n128tau128v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k128n128tau128v2/ref/api.h"
#define FILENAME "log_omdsha512k128n128tau128v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k128n128tau128v2/sse4/api.h"
#define FILENAME "log_omdsha512k128n128tau128v2_sse4.txt"
#endif
#endif

#ifdef omdsha512k256n256tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha512k256n256tau256v2/avx1/api.h"
#define FILENAME "log_omdsha512k256n256tau256v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k256n256tau256v2/ref/api.h"
#define FILENAME "log_omdsha512k256n256tau256v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k256n256tau256v2/sse4/api.h"
#define FILENAME "log_omdsha512k256n256tau256v2_sse4.txt"
#endif
#endif

#ifdef omdsha512k512n256tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha512k512n256tau256v2/avx1/api.h"
#define FILENAME "log_omdsha512k512n256tau256v2_avx1.txt"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k512n256tau256v2/ref/api.h"
#define FILENAME "log_omdsha512k512n256tau256v2_ref.txt"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k512n256tau256v2/sse4/api.h"
#define FILENAME "log_omdsha512k512n256tau256v2_sse4.txt"
#endif
#endif

#ifdef paeq128
#ifdef aesni
#include "../crypto_aead/paeq128/aesni/api.h"
#define FILENAME "log_paeq128_aesni.txt"
#endif
#ifdef optwinaes
#include "../crypto_aead/paeq128/optwinaes/api.h"
#define FILENAME "log_paeq128_optwinaes.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq128/ref/api.h"
#define FILENAME "log_paeq128_ref.txt"
#endif
#endif

#ifdef paeq128t
#ifdef aesni
#include "../crypto_aead/paeq128t/aesni/api.h"
#define FILENAME "log_paeq128t_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq128t/ref/api.h"
#define FILENAME "log_paeq128t_ref.txt"
#endif
#endif

#ifdef paeq128tnm
#ifdef aesni
#include "../crypto_aead/paeq128tnm/aesni/api.h"
#define FILENAME "log_paeq128tnm_aesni.txt"
#endif
#ifdef optwinaes
#include "../crypto_aead/paeq128tnm/optwinaes/api.h"
#define FILENAME "log_paeq128tnm_optwinaes.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq128tnm/ref/api.h"
#define FILENAME "log_paeq128tnm_ref.txt"
#endif
#endif

#ifdef paeq160
#ifdef aesni
#include "../crypto_aead/paeq160/aesni/api.h"
#define FILENAME "log_paeq160_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq160/ref/api.h"
#define FILENAME "log_paeq160_ref.txt"
#endif
#endif

#ifdef paeq64
#ifdef aesni
#include "../crypto_aead/paeq64/aesni/api.h"
#define FILENAME "log_paeq64_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq64/ref/api.h"
#define FILENAME "log_paeq64_ref.txt"
#endif
#endif

#ifdef paeq80
#ifdef aesni
#include "../crypto_aead/paeq80/aesni/api.h"
#define FILENAME "log_paeq80_aesni.txt"
#endif
#ifdef ref
#include "../crypto_aead/paeq80/ref/api.h"
#define FILENAME "log_paeq80_ref.txt"
#endif
#endif

#ifdef pi16cipher096v2
#ifdef ref
#include "../crypto_aead/pi16cipher096v2/ref/api.h"
#define FILENAME "log_pi16cipher096v2_ref.txt"
#endif
#endif

#ifdef pi16cipher128v2
#ifdef ref
#include "../crypto_aead/pi16cipher128v2/ref/api.h"
#define FILENAME "log_pi16cipher128v2_ref.txt"
#endif
#endif

#ifdef pi32cipher128v2
#ifdef ref
#include "../crypto_aead/pi32cipher128v2/ref/api.h"
#define FILENAME "log_pi32cipher128v2_ref.txt"
#endif
#endif

#ifdef pi32cipher256v2
#ifdef ref
#include "../crypto_aead/pi32cipher256v2/ref/api.h"
#define FILENAME "log_pi32cipher256v2_ref.txt"
#endif
#endif

#ifdef pi64cipher128v2
#ifdef ref
#include "../crypto_aead/pi64cipher128v2/ref/api.h"
#define FILENAME "log_pi64cipher128v2_ref.txt"
#endif
#endif

#ifdef pi64cipher256v2
#ifdef ref
#include "../crypto_aead/pi64cipher256v2/ref/api.h"
#define FILENAME "log_pi64cipher256v2_ref.txt"
#endif
#endif

#ifdef present80n6t4silcv2
#ifdef ref
#include "../crypto_aead/present80n6t4silcv2/ref/api.h"
#define FILENAME "log_present80n6t4silcv2_ref.txt"
#endif
#endif

#ifdef primatesv1ape120
#ifdef ref
#include "../crypto_aead/primatesv1ape120/ref/api.h"
#define FILENAME "log_primatesv1ape120_ref.txt"
#endif
#endif

#ifdef primatesv1ape80
#ifdef ref
#include "../crypto_aead/primatesv1ape80/ref/api.h"
#define FILENAME "log_primatesv1ape80_ref.txt"
#endif
#endif

#ifdef primatesv1gibbon120
#ifdef ref
#include "../crypto_aead/primatesv1gibbon120/ref/api.h"
#define FILENAME "log_primatesv1gibbon120_ref.txt"
#endif
#endif

#ifdef primatesv1gibbon80
#ifdef ref
#include "../crypto_aead/primatesv1gibbon80/ref/api.h"
#define FILENAME "log_primatesv1gibbon80_ref.txt"
#endif
#endif

#ifdef primatesv1hanuman120
#ifdef ref
#include "../crypto_aead/primatesv1hanuman120/ref/api.h"
#define FILENAME "log_primatesv1hanuman120_ref.txt"
#endif
#endif

#ifdef primatesv1hanuman80
#ifdef ref
#include "../crypto_aead/primatesv1hanuman80/ref/api.h"
#define FILENAME "log_primatesv1hanuman80_ref.txt"
#endif
#endif

#ifdef riverkeyakv2
#ifdef ARMv6M
#include "../crypto_aead/riverkeyakv2/ARMv6M/api.h"
#define FILENAME "log_riverkeyakv2_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/riverkeyakv2/ARMv7M/api.h"
#define FILENAME "log_riverkeyakv2_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/riverkeyakv2/AVR8/api.h"
#define FILENAME "log_riverkeyakv2_AVR8.txt"
#endif
#ifdef Bulldozer
#include "../crypto_aead/riverkeyakv2/Bulldozer/api.h"
#define FILENAME "log_riverkeyakv2_Bulldozer.txt"
#endif
#ifdef Haswell
#include "../crypto_aead/riverkeyakv2/Haswell/api.h"
#define FILENAME "log_riverkeyakv2_Haswell.txt"
#endif
#ifdef Nehalem
#include "../crypto_aead/riverkeyakv2/Nehalem/api.h"
#define FILENAME "log_riverkeyakv2_Nehalem.txt"
#endif
#ifdef SandyBridge
#include "../crypto_aead/riverkeyakv2/SandyBridge/api.h"
#define FILENAME "log_riverkeyakv2_SandyBridge.txt"
#endif
#ifdef compact
#include "../crypto_aead/riverkeyakv2/compact/api.h"
#define FILENAME "log_riverkeyakv2_compact.txt"
#endif
#ifdef generic32
#include "../crypto_aead/riverkeyakv2/generic32/api.h"
#define FILENAME "log_riverkeyakv2_generic32.txt"
#endif
#ifdef generic32lc
#include "../crypto_aead/riverkeyakv2/generic32lc/api.h"
#define FILENAME "log_riverkeyakv2_generic32lc.txt"
#endif
#ifdef generic64
#include "../crypto_aead/riverkeyakv2/generic64/api.h"
#define FILENAME "log_riverkeyakv2_generic64.txt"
#endif
#ifdef generic64lc
#include "../crypto_aead/riverkeyakv2/generic64lc/api.h"
#define FILENAME "log_riverkeyakv2_generic64lc.txt"
#endif
#ifdef reference
#include "../crypto_aead/riverkeyakv2/reference/api.h"
#define FILENAME "log_riverkeyakv2_reference.txt"
#endif
#ifdef reference32bits
#include "../crypto_aead/riverkeyakv2/reference32bits/api.h"
#define FILENAME "log_riverkeyakv2_reference32bits.txt"
#endif
#endif

#ifdef scream10v3
#ifdef neon
#include "../crypto_aead/scream10v3/neon/api.h"
#define FILENAME "log_scream10v3_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/scream10v3/ref/api.h"
#define FILENAME "log_scream10v3_ref.txt"
#endif
#ifdef sse
#include "../crypto_aead/scream10v3/sse/api.h"
#define FILENAME "log_scream10v3_sse.txt"
#endif
#endif

#ifdef scream12v3
#ifdef neon
#include "../crypto_aead/scream12v3/neon/api.h"
#define FILENAME "log_scream12v3_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/scream12v3/ref/api.h"
#define FILENAME "log_scream12v3_ref.txt"
#endif
#ifdef sse
#include "../crypto_aead/scream12v3/sse/api.h"
#define FILENAME "log_scream12v3_sse.txt"
#endif
#endif

#ifdef seakeyakv2
#ifdef ARMv6M
#include "../crypto_aead/seakeyakv2/ARMv6M/api.h"
#define FILENAME "log_seakeyakv2_ARMv6M.txt"
#endif
#ifdef ARMv7M
#include "../crypto_aead/seakeyakv2/ARMv7M/api.h"
#define FILENAME "log_seakeyakv2_ARMv7M.txt"
#endif
#ifdef AVR8
#include "../crypto_aead/seakeyakv2/AVR8/api.h"
#define FILENAME "log_seakeyakv2_AVR8.txt"
#endif
#ifdef Bulldozer
#include "../crypto_aead/seakeyakv2/Bulldozer/api.h"
#define FILENAME "log_seakeyakv2_Bulldozer.txt"
#endif
#ifdef Haswell
#include "../crypto_aead/seakeyakv2/Haswell/api.h"
#define FILENAME "log_seakeyakv2_Haswell.txt"
#endif
#ifdef Nehalem
#include "../crypto_aead/seakeyakv2/Nehalem/api.h"
#define FILENAME "log_seakeyakv2_Nehalem.txt"
#endif
#ifdef SandyBridge
#include "../crypto_aead/seakeyakv2/SandyBridge/api.h"
#define FILENAME "log_seakeyakv2_SandyBridge.txt"
#endif
#ifdef asmX8664
#include "../crypto_aead/seakeyakv2/asmX8664/api.h"
#define FILENAME "log_seakeyakv2_asmX8664.txt"
#endif
#ifdef asmX8664shld
#include "../crypto_aead/seakeyakv2/asmX8664shld/api.h"
#define FILENAME "log_seakeyakv2_asmX8664shld.txt"
#endif
#ifdef compact
#include "../crypto_aead/seakeyakv2/compact/api.h"
#define FILENAME "log_seakeyakv2_compact.txt"
#endif
#ifdef generic32
#include "../crypto_aead/seakeyakv2/generic32/api.h"
#define FILENAME "log_seakeyakv2_generic32.txt"
#endif
#ifdef generic32lc
#include "../crypto_aead/seakeyakv2/generic32lc/api.h"
#define FILENAME "log_seakeyakv2_generic32lc.txt"
#endif
#ifdef generic64
#include "../crypto_aead/seakeyakv2/generic64/api.h"
#define FILENAME "log_seakeyakv2_generic64.txt"
#endif
#ifdef generic64lc
#include "../crypto_aead/seakeyakv2/generic64lc/api.h"
#define FILENAME "log_seakeyakv2_generic64lc.txt"
#endif
#ifdef reference32bits
#include "../crypto_aead/seakeyakv2/reference32bits/api.h"
#define FILENAME "log_seakeyakv2_reference32bits.txt"
#endif
#endif

#ifdef shellaes128v2d4n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d4n64/ref/api.h"
#define FILENAME "log_shellaes128v2d4n64_ref.txt"
#endif
#endif

#ifdef shellaes128v2d4n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d4n80/ref/api.h"
#define FILENAME "log_shellaes128v2d4n80_ref.txt"
#endif
#endif

#ifdef shellaes128v2d5n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d5n64/ref/api.h"
#define FILENAME "log_shellaes128v2d5n64_ref.txt"
#endif
#endif

#ifdef shellaes128v2d5n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d5n80/ref/api.h"
#define FILENAME "log_shellaes128v2d5n80_ref.txt"
#endif
#endif

#ifdef shellaes128v2d6n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d6n64/ref/api.h"
#define FILENAME "log_shellaes128v2d6n64_ref.txt"
#endif
#endif

#ifdef shellaes128v2d6n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d6n80/ref/api.h"
#define FILENAME "log_shellaes128v2d6n80_ref.txt"
#endif
#endif

#ifdef shellaes128v2d7n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d7n64/ref/api.h"
#define FILENAME "log_shellaes128v2d7n64_ref.txt"
#endif
#endif

#ifdef shellaes128v2d7n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d7n80/ref/api.h"
#define FILENAME "log_shellaes128v2d7n80_ref.txt"
#endif
#endif

#ifdef shellaes128v2d8n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d8n64/ref/api.h"
#define FILENAME "log_shellaes128v2d8n64_ref.txt"
#endif
#endif

#ifdef shellaes128v2d8n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d8n80/ref/api.h"
#define FILENAME "log_shellaes128v2d8n80_ref.txt"
#endif
#endif

#ifdef simonjambu128v2
#ifdef ref
#include "../crypto_aead/simonjambu128v2/ref/api.h"
#define FILENAME "log_simonjambu128v2_ref.txt"
#endif
#endif

#ifdef simonjambu64v2
#ifdef ref
#include "../crypto_aead/simonjambu64v2/ref/api.h"
#define FILENAME "log_simonjambu64v2_ref.txt"
#endif
#endif

#ifdef simonjambu96v2
#ifdef ref
#include "../crypto_aead/simonjambu96v2/ref/api.h"
#define FILENAME "log_simonjambu96v2_ref.txt"
#endif
#endif

#ifdef stribob192r2
#ifdef _8bit
#include "../crypto_aead/stribob192r2/_8bit/api.h"
#define FILENAME "log_stribob192r2__8bit.txt"
#endif
#ifdef bitslice
#include "../crypto_aead/stribob192r2/bitslice/api.h"
#define FILENAME "log_stribob192r2_bitslice.txt"
#endif
#ifdef neon
#include "../crypto_aead/stribob192r2/neon/api.h"
#define FILENAME "log_stribob192r2_neon.txt"
#endif
#ifdef ref
#include "../crypto_aead/stribob192r2/ref/api.h"
#define FILENAME "log_stribob192r2_ref.txt"
#endif
#ifdef smaller
#include "../crypto_aead/stribob192r2/smaller/api.h"
#define FILENAME "log_stribob192r2_smaller.txt"
#endif
#ifdef ssse3
#include "../crypto_aead/stribob192r2/ssse3/api.h"
#define FILENAME "log_stribob192r2_ssse3.txt"
#endif
#endif

#ifdef tiaoxinv2
#ifdef nim
#include "../crypto_aead/tiaoxinv2/nim/api.h"
#define FILENAME "log_tiaoxinv2_nim.txt"
#endif
#ifdef ref
#include "../crypto_aead/tiaoxinv2/ref/api.h"
#define FILENAME "log_tiaoxinv2_ref.txt"
#endif
#endif

#ifdef trivia0v2
#ifdef ref
#include "../crypto_aead/trivia0v2/ref/api.h"
#define FILENAME "log_trivia0v2_ref.txt"
#endif
#endif

#ifdef trivia128v2
#ifdef ref
#include "../crypto_aead/trivia128v2/ref/api.h"
#define FILENAME "log_trivia128v2_ref.txt"
#endif
#endif

#ifdef twine80n6t4clocv2
#ifdef ref
#include "../crypto_aead/twine80n6t4clocv2/ref/api.h"
#define FILENAME "log_twine80n6t4clocv2_ref.txt"
#endif
#ifdef vperm
#include "../crypto_aead/twine80n6t4clocv2/vperm/api.h"
#define FILENAME "log_twine80n6t4clocv2_vperm.txt"
#endif
#endif

#define MEASUREMENT_CNT 200
#define MEAN_CNT 91

#define AD_MAX_ENTRIES 100
#define MSG_MAX_ENTRIES 100

//variables
struct parameters {
    int testcase_id;
    int ad[AD_MAX_ENTRIES];
    int ad_size;
    int msg[MSG_MAX_ENTRIES];
    int msg_size;
};
struct parameters p;

int varnonce = 0;
int varkey = 0;

//prototypes
long int getTimeStampCounterFrequency();
void writeHeader();
int comp (const void * elem1, const void * elem2);
void prettyPrint(double cyle_per_byte, uint64_t adlen, uint64_t mlen);
extern inline uint64_t rdtscp();


// This benchmark checks the key setup time of the primitives
// Message = constant
// Key = variable
// Nonce = variable
int benchAEAD(){
	unsigned char key[CRYPTO_KEYBYTES];
	unsigned char npub[CRYPTO_NPUBBYTES];
	unsigned char nsec[CRYPTO_NSECBYTES];
	
	long long unsigned int clen, mlen, adlen;
	
	unsigned char *ciphertext = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ad = NULL;
	
	memset(npub, 0x00, sizeof(unsigned char) * CRYPTO_NPUBBYTES);
	memset(nsec, 0x00, sizeof(unsigned char) * CRYPTO_NSECBYTES);
    memset(key, 0x42, sizeof(unsigned char) * CRYPTO_KEYBYTES);
	
	writeHeader();
	
	unsigned long long x[MEASUREMENT_CNT];
	unsigned long long y[MEASUREMENT_CNT];
	double time_diff[MEAN_CNT];
	
	printf("start measurement\n");
	
	int count = 0; //counter for nonce

    int ac = 0;
	for (; ac < p.ad_size; ac++){
        adlen = p.ad[ac];
    
		ad = malloc(adlen*sizeof(unsigned char));
		memset(ad, 'B', adlen);
		
        int jc = 0;
		for (; jc < p.msg_size; jc++){
            mlen = p.msg[jc];
            
			plaintext = malloc(mlen*sizeof(unsigned char));
			ciphertext = malloc((mlen+CRYPTO_ABYTES)*sizeof(unsigned char)); // ciphertext = ciphertext+tag
			memset(plaintext, 'A', mlen);
			memset(ciphertext, 0x0, (mlen+CRYPTO_ABYTES));
			
            if(varkey){
                //generate random key
                memset(key, (rand() % 256), sizeof(unsigned char) * CRYPTO_KEYBYTES);
            }
			
            if(varnonce){
                int c = 0;
                for(; c < CRYPTO_NPUBBYTES; c++){
                    npub[c] = (count >> (c*8)) & 0xff;
                }
                count++;
            }
      
			
			uint64_t i = 0;
			for (; i < MEAN_CNT; i++){
				uint64_t o = 0;
				for(; o < MEASUREMENT_CNT; o++){
        
        

        
					x[o] = 0; y[o] = 0;
					x[o] = rdtscp();
					crypto_aead_encrypt(ciphertext,&clen,plaintext,mlen,ad,adlen,nsec,npub,key);
					y[o] = rdtscp();
				}
				
				time_diff[i] = 0;
				for(o = 0; o < MEASUREMENT_CNT; o++){
					time_diff[i] += (y[o] - x[o]);
				}
				time_diff[i] /= MEASUREMENT_CNT;
			}
			
			double cyle_per_byte[MEAN_CNT];
			for(i = 0; i < MEAN_CNT; i++){
				cyle_per_byte[i] = (time_diff[i])/(mlen + adlen);
				// printf("%02f\n", cyle_per_byte[i]);
			}
			
			qsort(cyle_per_byte, sizeof(cyle_per_byte)/sizeof(*cyle_per_byte), sizeof(*cyle_per_byte), comp);
			prettyPrint(cyle_per_byte[MEAN_CNT/2], adlen, mlen);
			
			free(plaintext);
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
		}
		free(ad);
		ad = NULL;
	}
	
	return 0;
}

inline uint64_t rdtscp() {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtscp\n" : "=a" (lo), "=d" (hi));
    return (uint64_t)hi << 32 | lo;
}

long int getTimeStampCounterFrequency(){
    FILE *fp = NULL;
    char file_type[40];
    char test[11];
	
    fp = popen("sysctl -a machdep.tsc.frequency", "r");
    while (fgets(file_type, sizeof(file_type), fp) != NULL);
    pclose(fp);
    
    strncpy(test, file_type+23, 10);
    
    return atol(test);
}

void writeHeader(){
    FILE *log = fopen(FILENAME, "a");
    fprintf(log, "TESTCASE_ID=%d;AD_ENTRIES=%d;MSG_ENTRIES=%d;\n", p.testcase_id, p.ad_size, p.msg_size);
    fprintf(log, "implementation;cyle_per_byte;message_length;ad_length\n");
    fclose(log);
}

int comp (const void *elem1, const void *elem2){
    double f = *((double*)elem1);
    double s = *((double*)elem2);
    if (f > s) return  1;
    if (f < s) return -1;
    return 0;
}

void prettyPrint(double cyle_per_byte, uint64_t adlen, uint64_t mlen){
    
    FILE *log = fopen(FILENAME, "a");
  
    #ifdef ref
    fprintf(log, "ref;");
    #endif
    #ifdef reference
    fprintf(log, "reference;");
    #endif
    #ifdef reference32bits
    fprintf(log, "reference32bits;");
    #endif
    #ifdef ref64
    fprintf(log, "ref64;");
    #endif
    #ifdef opt
    fprintf(log, "opt;");
    #endif
    #ifdef opt64
    fprintf(log, "opt64;");
    #endif
    #ifdef optwinaes
    fprintf(log, "opt-win-aes;");
    #endif
    #ifdef compact
    fprintf(log, "compact;");
    #endif
    #ifdef smaller
    fprintf(log, "smaller;");
    #endif
    #ifdef nim
    fprintf(log, "nim;");
    #endif
    #ifdef vperm
    fprintf(log, "vperm;");
    #endif
    #ifdef generic32
    fprintf(log, "generic32;");
    #endif
    #ifdef generic32lc
    fprintf(log, "generic32lc;");
    #endif
    #ifdef generic64
    fprintf(log, "generic64;");
    #endif
    #ifdef generic64lc
    fprintf(log, "generic64lc;");
    #endif
    #ifdef _8bit
    fprintf(log, "_8bit;");
    #endif
    #ifdef aesni
    fprintf(log, "aesni;");
    #endif
    #ifdef aesnia
    fprintf(log, "aesnia;");
    #endif
    #ifdef aesnib
    fprintf(log, "aesnib;");
    #endif
    #ifdef aesnic
    fprintf(log, "aesnic;");
    #endif
    #ifdef ni
    fprintf(log, "ni;");
    #endif
    #ifdef nip7m1
    fprintf(log, "nip7m1;");
    #endif
    #ifdef nip7m2
    fprintf(log, "nip7m2;");
    #endif
    #ifdef nip8m1
    fprintf(log, "nip8m1;");
    #endif
    #ifdef nip8m2
    fprintf(log, "nip8m2;");
    #endif
    #ifdef sse
    fprintf(log, "sse;");
    #endif
    #ifdef sse2
    fprintf(log, "sse2;");
    #endif
    #ifdef ssse3
    fprintf(log, "ssse3;");
    #endif
    #ifdef sse4
    fprintf(log, "sse4;");
    #endif
    #ifdef avx1
    fprintf(log, "avx1;");
    #endif
    #ifdef avx2
    fprintf(log, "avx2;");
    #endif
    #ifdef xmm
    fprintf(log, "xmm;");
    #endif
    #ifdef ymm
    fprintf(log, "ymm;");
    #endif
    #ifdef neon
    fprintf(log, "neon;");
    #endif
    #ifdef bitslice
    fprintf(log, "bitslice;");
    #endif
    #ifdef asmX8664
    fprintf(log, "asmX8664;");
    #endif
    #ifdef asmX8664shld
    fprintf(log, "asmX8664shld;");
    #endif
    #ifdef Bulldozer
    fprintf(log, "Bulldozer;");
    #endif
    #ifdef Haswell
    fprintf(log, "Haswell;");
    #endif
    #ifdef Nehalem
    fprintf(log, "Nehalem;");
    #endif
    #ifdef SandyBridge
    fprintf(log, "SandyBridge;");
    #endif
    #ifdef ARMv6M
    fprintf(log, "ARMv6M;");
    #endif
    #ifdef ARMv7M
    fprintf(log, "ARMv7M;");
    #endif
    #ifdef AVR8
    fprintf(log, "AVR8;");
    #endif
    #ifdef openssl
    fprintf(log, "openssl;");
    #endif
    #ifdef cryptopp
    fprintf(log, "cryptopp;");
    #endif
  
    fprintf(log, "%.2f;", cyle_per_byte);
    fprintf(log, "%llu;", mlen);
    fprintf(log, "%llu;\n", adlen);
    fclose(log);
}

//##############################################################################

#define NR_OF_TESTCASES 2

int main(int argc, char** argv)
{

    /* settings for the measurement process */
    FILE *log = fopen(FILENAME, "a");
    fprintf(log, "NR_OF_TESTCASES=%d\n", NR_OF_TESTCASES);
    fclose(log);
  
  
    // Measurements with variable length's
    /*int ad = 0;
    for (; ad <= 2048; ad+=128) {
        p.ad[ad/128] = ad;
    }
    p.ad_size = (2048/128)+1;*/
  
    p.ad[0] = 0;
    p.ad_size = 1;
    
    int msg = 0;
    for (; msg <= 2048; msg+=128) {
        p.msg[msg/128] = msg;
    }
    p.msg_size = (2048/128)+1;
  
   /* p.testcase_id = 1;
    benchAEAD();*/
  
    varnonce = 1;
    p.testcase_id = 2;
    benchAEAD();
  
    /*varnonce = 1;
    varkey = 1;
    p.testcase_id = 3;
    benchAEAD();*/
    
    
    /*
     Measurements with fixed length's
     
     + same message, key constant, nonce changes every time
     - message size:  16 bytes, associated data: 5bytes, small payload
     - message size: 557 bytes, associated data: 5bytes, average ip packet
     - message size:  16 KB,    associated data: 5bytes, large payload (max TCP paket)
     - message size:   1 MB,    associated data: 5bytes, HUGE payload (fileupload)
     
     + same message, key/nonce changes every time (key setup)
     - as above
     
     + same message, key/nonce constant (nonce-missuse)
     - as above
     
         // 1 byte = 1 key stroke (SSH)
         // 1.5kB = ethernet frame (TLS)
     */
  
    varnonce = 0;
    varkey = 0;
  
    p.ad[0] = 5;
    p.ad_size = 1;
  
    p.msg[0] = 1;
    p.msg[1] = 16;
    p.msg[2] = 557;
    p.msg[3] = 1500;
    p.msg[4] = 16000;
    p.msg[5] = 1000000;
    p.msg_size = 6;
    
    /*p.testcase_id = 1;
    benchAEAD();*/
    
    varnonce = 1;
    p.testcase_id = 2;
    benchAEAD();
    
    /*varkey = 1;
    p.testcase_id = 3;
    benchAEAD();*/
  

  
    /*varnonce = 0;
    varkey = 0;
  
    p.ad[0] = 5;
    p.ad_size = 1;
    
    p.msg[0] = 1;
    p.msg[1] = 1500;
    p.msg_size = 2;
    
    p.testcase_id = 1;
    varnonce = 1;
    benchAEAD();*/
    
	return 0;
}




