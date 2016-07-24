// todo header, license and stuff
// author: Ralph Ankele (ralph.ankele.2015@live.rhul.ac.uk)


#include <stdio.h>
#include <stdlib.h>

#include "crypto_aead.h"

#ifdef acorn128v2
#ifdef opt
#include "../crypto_aead/acorn128v2/opt/api.h"
#endif
#ifdef ref
#include "../crypto_aead/acorn128v2/ref/api.h"
#endif
#endif

#ifdef aeadaes128ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes128ocbtaglen128v1/opt/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen128v1/ref/api.h"
#endif
#endif

#ifdef aeadaes128ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen64v1/ref/api.h"
#endif
#endif

#ifdef aeadaes128ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes128ocbtaglen96v1/ref/api.h"
#endif
#endif

#ifdef aeadaes192ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes192ocbtaglen128v1/opt/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen128v1/ref/api.h"
#endif
#endif

#ifdef aeadaes192ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen64v1/ref/api.h"
#endif
#endif

#ifdef aeadaes192ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes192ocbtaglen96v1/ref/api.h"
#endif
#endif

#ifdef aeadaes256ocbtaglen128v1
#ifdef opt
#include "../crypto_aead/aeadaes256ocbtaglen128v1/opt/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen128v1/ref/api.h"
#endif
#endif

#ifdef aeadaes256ocbtaglen64v1
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen64v1/ref/api.h"
#endif
#endif

#ifdef aeadaes256ocbtaglen96v1
#ifdef ref
#include "../crypto_aead/aeadaes256ocbtaglen96v1/ref/api.h"
#endif
#endif

#ifdef aegis128
#ifdef aesni
#include "../crypto_aead/aegis128/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aegis128/ref/api.h"
#endif
#endif

#ifdef aegis128l
#ifdef aesnia
#include "../crypto_aead/aegis128l/aesnia/api.h"
#endif
#ifdef aesnib
#include "../crypto_aead/aegis128l/aesnib/api.h"
#endif
#ifdef aesnic
#include "../crypto_aead/aegis128l/aesnic/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aegis128l/ref/api.h"
#endif
#endif

#ifdef aegis256
#ifdef aesni
#include "../crypto_aead/aegis256/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aegis256/ref/api.h"
#endif
#endif

#ifdef aes128n12t8clocv2
#ifdef aesni
#include "../crypto_aead/aes128n12t8clocv2/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128n12t8clocv2/ref/api.h"
#endif
#endif

#ifdef aes128n12t8silcv2
#ifdef aesni
#include "../crypto_aead/aes128n12t8silcv2/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128n12t8silcv2/ref/api.h"
#endif
#endif

#ifdef aes128n8t8clocv2
#ifdef aesni
#include "../crypto_aead/aes128n8t8clocv2/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128n8t8clocv2/ref/api.h"
#endif
#endif

#ifdef aes128n8t8silcv2
#ifdef aesni
#include "../crypto_aead/aes128n8t8silcv2/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128n8t8silcv2/ref/api.h"
#endif
#endif

#ifdef aes128otrpv2
#ifdef ref
#include "../crypto_aead/aes128otrpv2/ref/api.h"
#endif
#endif

#ifdef aes128otrsv2
#ifdef ref
#include "../crypto_aead/aes128otrsv2/ref/api.h"
#endif
#endif

#ifdef aes128poetv2aes128ls0lt0
#ifdef ni
#include "../crypto_aead/aes128poetv2aes128ls0lt0/ni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128poetv2aes128ls0lt0/ref/api.h"
#endif
#endif

#ifdef aes128poetv2aes128ls128lt128
#ifdef ref
#include "../crypto_aead/aes128poetv2aes128ls128lt128/ref/api.h"
#endif
#endif

#ifdef aes128poetv2aes4ls0lt0
#ifdef ni
#include "../crypto_aead/aes128poetv2aes4ls0lt0/ni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aes128poetv2aes4ls0lt0/ref/api.h"
#endif
#endif

#ifdef aes128poetv2aes4ls128lt128
#ifdef ref
#include "../crypto_aead/aes128poetv2aes4ls128lt128/ref/api.h"
#endif
#endif

#ifdef aes256otrpv2
#ifdef ref
#include "../crypto_aead/aes256otrpv2/ref/api.h"
#endif
#endif

#ifdef aes256otrsv2
#ifdef ref
#include "../crypto_aead/aes256otrsv2/ref/api.h"
#endif
#endif

#ifdef aesjambuv2
#ifdef aesni
#include "../crypto_aead/aesjambuv2/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aesjambuv2/ref/api.h"
#endif
#endif

#ifdef aezv4
#ifdef aesni
#include "../crypto_aead/aezv4/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/aezv4/ref/api.h"
#endif
#endif

#ifdef ascon128av11
#ifdef opt64
#include "../crypto_aead/ascon128av11/opt64/api.h"
#endif
#ifdef ref
#include "../crypto_aead/ascon128av11/ref/api.h"
#endif
#endif

#ifdef ascon128v11
#ifdef opt64
#include "../crypto_aead/ascon128v11/opt64/api.h"
#endif
#ifdef ref
#include "../crypto_aead/ascon128v11/ref/api.h"
#endif
#endif

#ifdef deoxyseq128128v13
#ifdef ref
#include "../crypto_aead/deoxyseq128128v13/ref/api.h"
#endif
#endif

#ifdef deoxyseq256128v13
#ifdef ref
#include "../crypto_aead/deoxyseq256128v13/ref/api.h"
#endif
#endif

#ifdef deoxysneq128128v13
#ifdef aesni
#include "../crypto_aead/deoxysneq128128v13/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/deoxysneq128128v13/ref/api.h"
#endif
#endif

#ifdef deoxysneq256128v13
#ifdef aesni
#include "../crypto_aead/deoxysneq256128v13/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/deoxysneq256128v13/ref/api.h"
#endif
#endif

#ifdef elmd1000v2
#ifdef ref
#include "../crypto_aead/elmd1000v2/ref/api.h"
#endif
#endif

#ifdef elmd1001v2
#ifdef ref
#include "../crypto_aead/elmd1001v2/ref/api.h"
#endif
#endif

#ifdef elmd101270v2
#ifdef ref
#include "../crypto_aead/elmd101270v2/ref/api.h"
#endif
#endif

#ifdef elmd101271v2
#ifdef ref
#include "../crypto_aead/elmd101271v2/ref/api.h"
#endif
#endif

#ifdef elmd600v2
#ifdef ref
#include "../crypto_aead/elmd600v2/ref/api.h"
#endif
#endif

#ifdef elmd601v2
#ifdef ref
#include "../crypto_aead/elmd601v2/ref/api.h"
#endif
#endif

#ifdef elmd61270v2
#ifdef ref
#include "../crypto_aead/elmd61270v2/ref/api.h"
#endif
#endif

#ifdef elmd61271v2
#ifdef ref
#include "../crypto_aead/elmd61271v2/ref/api.h"
#endif
#endif

#ifdef hs1sivhiv1
#ifdef ref
#include "../crypto_aead/hs1sivhiv1/ref/api.h"
#endif
#endif

#ifdef hs1sivlov1
#ifdef ref
#include "../crypto_aead/hs1sivlov1/ref/api.h"
#endif
#endif

#ifdef hs1sivv1
#ifdef ref
#include "../crypto_aead/hs1sivv1/ref/api.h"
#endif
#endif

#ifdef icepole128av2
#ifdef ref
#include "../crypto_aead/icepole128av2/ref/api.h"
#endif
#endif

#ifdef icepole128v2
#ifdef ref
#include "../crypto_aead/icepole128v2/ref/api.h"
#endif
#endif

#ifdef icepole256av2
#ifdef ref
#include "../crypto_aead/icepole256av2/ref/api.h"
#endif
#endif

#ifdef joltikeq12864v13
#ifdef ref
#include "../crypto_aead/joltikeq12864v13/ref/api.h"
#endif
#endif

#ifdef joltikeq6464v13
#ifdef ref
#include "../crypto_aead/joltikeq6464v13/ref/api.h"
#endif
#endif

#ifdef joltikeq80112v13
#ifdef ref
#include "../crypto_aead/joltikeq80112v13/ref/api.h"
#endif
#endif

#ifdef joltikeq9696v13
#ifdef ref
#include "../crypto_aead/joltikeq9696v13/ref/api.h"
#endif
#endif

#ifdef joltikneq12864v13
#ifdef ref
#include "../crypto_aead/joltikneq12864v13/ref/api.h"
#endif
#endif

#ifdef joltikneq6464v13
#ifdef ref
#include "../crypto_aead/joltikneq6464v13/ref/api.h"
#endif
#endif

#ifdef joltikneq80112v13
#ifdef ref
#include "../crypto_aead/joltikneq80112v13/ref/api.h"
#endif
#endif

#ifdef joltikneq9696v13
#ifdef ref
#include "../crypto_aead/joltikneq9696v13/ref/api.h"
#endif
#endif

#ifdef ketjejrv1
#ifdef ARMv6M
#include "../crypto_aead/ketjejrv1/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/ketjejrv1/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/ketjejrv1/AVR8/api.h"
#endif
#ifdef compact
#include "../crypto_aead/ketjejrv1/compact/api.h"
#endif
#ifdef reference
#include "../crypto_aead/ketjejrv1/reference/api.h"
#endif
#endif

#ifdef ketjesrv1
#ifdef ARMv6M
#include "../crypto_aead/ketjesrv1/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/ketjesrv1/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/ketjesrv1/AVR8/api.h"
#endif
#ifdef compact
#include "../crypto_aead/ketjesrv1/compact/api.h"
#endif
#ifdef reference
#include "../crypto_aead/ketjesrv1/reference/api.h"
#endif
#endif

#ifdef lakekeyakv2
#ifdef ARMv6M
#include "../crypto_aead/lakekeyakv2/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/lakekeyakv2/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/lakekeyakv2/AVR8/api.h"
#endif
#ifdef Bulldozer
#include "../crypto_aead/lakekeyakv2/Bulldozer/api.h"
#endif
#ifdef Haswell
#include "../crypto_aead/lakekeyakv2/Haswell/api.h"
#endif
#ifdef Nehalem
#include "../crypto_aead/lakekeyakv2/Nehalem/api.h"
#endif
#ifdef SandyBridge
#include "../crypto_aead/lakekeyakv2/SandyBridge/api.h"
#endif
#ifdef asmX86-64
#include "../crypto_aead/lakekeyakv2/asmX86-64/api.h"
#endif
#ifdef asmX86-64shld
#include "../crypto_aead/lakekeyakv2/asmX86-64shld/api.h"
#endif
#ifdef compact
#include "../crypto_aead/lakekeyakv2/compact/api.h"
#endif
#ifdef generic32
#include "../crypto_aead/lakekeyakv2/generic32/api.h"
#endif
#ifdef generic32lc
#include "../crypto_aead/lakekeyakv2/generic32lc/api.h"
#endif
#ifdef generic64
#include "../crypto_aead/lakekeyakv2/generic64/api.h"
#endif
#ifdef generic64lc
#include "../crypto_aead/lakekeyakv2/generic64lc/api.h"
#endif
#ifdef reference32bits
#include "../crypto_aead/lakekeyakv2/reference32bits/api.h"
#endif
#endif

#ifdef led80n6t4silcv2
#ifdef ref
#include "../crypto_aead/led80n6t4silcv2/ref/api.h"
#endif
#endif

#ifdef lunarkeyakv2
#ifdef ARMv6M
#include "../crypto_aead/lunarkeyakv2/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/lunarkeyakv2/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/lunarkeyakv2/AVR8/api.h"
#endif
#ifdef Bulldozer
#include "../crypto_aead/lunarkeyakv2/Bulldozer/api.h"
#endif
#ifdef Haswell
#include "../crypto_aead/lunarkeyakv2/Haswell/api.h"
#endif
#ifdef Nehalem
#include "../crypto_aead/lunarkeyakv2/Nehalem/api.h"
#endif
#ifdef SandyBridge
#include "../crypto_aead/lunarkeyakv2/SandyBridge/api.h"
#endif
#ifdef asmX86-64
#include "../crypto_aead/lunarkeyakv2/asmX86-64/api.h"
#endif
#ifdef asmX86-64shld
#include "../crypto_aead/lunarkeyakv2/asmX86-64shld/api.h"
#endif
#ifdef compact
#include "../crypto_aead/lunarkeyakv2/compact/api.h"
#endif
#ifdef generic32
#include "../crypto_aead/lunarkeyakv2/generic32/api.h"
#endif
#ifdef generic32lc
#include "../crypto_aead/lunarkeyakv2/generic32lc/api.h"
#endif
#ifdef generic64
#include "../crypto_aead/lunarkeyakv2/generic64/api.h"
#endif
#ifdef generic64lc
#include "../crypto_aead/lunarkeyakv2/generic64lc/api.h"
#endif
#ifdef reference32bits
#include "../crypto_aead/lunarkeyakv2/reference32bits/api.h"
#endif
#endif

#ifdef minalpherv11
#ifdef avx2
#include "../crypto_aead/minalpherv11/avx2/api.h"
#endif
#ifdef ref
#include "../crypto_aead/minalpherv11/ref/api.h"
#endif
#endif

#ifdef morus1280128v1
#ifdef avx2
#include "../crypto_aead/morus1280128v1/avx2/api.h"
#endif
#ifdef ref
#include "../crypto_aead/morus1280128v1/ref/api.h"
#endif
#ifdef ref64
#include "../crypto_aead/morus1280128v1/ref64/api.h"
#endif
#ifdef sse2
#include "../crypto_aead/morus1280128v1/sse2/api.h"
#endif
#endif

#ifdef morus1280256v1
#ifdef avx2
#include "../crypto_aead/morus1280256v1/avx2/api.h"
#endif
#ifdef ref
#include "../crypto_aead/morus1280256v1/ref/api.h"
#endif
#ifdef ref64
#include "../crypto_aead/morus1280256v1/ref64/api.h"
#endif
#ifdef sse2
#include "../crypto_aead/morus1280256v1/sse2/api.h"
#endif
#endif

#ifdef morus640128v1
#ifdef ref
#include "../crypto_aead/morus640128v1/ref/api.h"
#endif
#ifdef sse2
#include "../crypto_aead/morus640128v1/sse2/api.h"
#endif
#endif

#ifdef norx0841
#ifdef ref
#include "../crypto_aead/norx0841/ref/api.h"
#endif
#endif

#ifdef norx1641
#ifdef ref
#include "../crypto_aead/norx1641/ref/api.h"
#endif
#endif

#ifdef norx3241
#ifdef neon
#include "../crypto_aead/norx3241/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/norx3241/ref/api.h"
#endif
#ifdef xmm
#include "../crypto_aead/norx3241/xmm/api.h"
#endif
#endif

#ifdef norx3261
#ifdef neon
#include "../crypto_aead/norx3261/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/norx3261/ref/api.h"
#endif
#ifdef xmm
#include "../crypto_aead/norx3261/xmm/api.h"
#endif
#endif

#ifdef norx6441
#ifdef neon
#include "../crypto_aead/norx6441/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/norx6441/ref/api.h"
#endif
#ifdef xmm
#include "../crypto_aead/norx6441/xmm/api.h"
#endif
#ifdef ymm
#include "../crypto_aead/norx6441/ymm/api.h"
#endif
#endif

#ifdef norx6444
#ifdef ref
#include "../crypto_aead/norx6444/ref/api.h"
#endif
#endif

#ifdef norx6461
#ifdef neon
#include "../crypto_aead/norx6461/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/norx6461/ref/api.h"
#endif
#ifdef xmm
#include "../crypto_aead/norx6461/xmm/api.h"
#endif
#ifdef ymm
#include "../crypto_aead/norx6461/ymm/api.h"
#endif
#endif

#ifdef oceankeyakv2
#ifdef ARMv6M
#include "../crypto_aead/oceankeyakv2/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/oceankeyakv2/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/oceankeyakv2/AVR8/api.h"
#endif
#ifdef Bulldozer
#include "../crypto_aead/oceankeyakv2/Bulldozer/api.h"
#endif
#ifdef Haswell
#include "../crypto_aead/oceankeyakv2/Haswell/api.h"
#endif
#ifdef Nehalem
#include "../crypto_aead/oceankeyakv2/Nehalem/api.h"
#endif
#ifdef SandyBridge
#include "../crypto_aead/oceankeyakv2/SandyBridge/api.h"
#endif
#ifdef asmX86-64
#include "../crypto_aead/oceankeyakv2/asmX86-64/api.h"
#endif
#ifdef asmX86-64shld
#include "../crypto_aead/oceankeyakv2/asmX86-64shld/api.h"
#endif
#ifdef compact
#include "../crypto_aead/oceankeyakv2/compact/api.h"
#endif
#ifdef generic32
#include "../crypto_aead/oceankeyakv2/generic32/api.h"
#endif
#ifdef generic32lc
#include "../crypto_aead/oceankeyakv2/generic32lc/api.h"
#endif
#ifdef generic64
#include "../crypto_aead/oceankeyakv2/generic64/api.h"
#endif
#ifdef generic64lc
#include "../crypto_aead/oceankeyakv2/generic64lc/api.h"
#endif
#ifdef reference32bits
#include "../crypto_aead/oceankeyakv2/reference32bits/api.h"
#endif
#endif

#ifdef omdsha256k128n96tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau128v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau128v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau128v2/sse4/api.h"
#endif
#endif

#ifdef omdsha256k128n96tau64v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau64v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau64v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau64v2/sse4/api.h"
#endif
#endif

#ifdef omdsha256k128n96tau96v2
#ifdef avx1
#include "../crypto_aead/omdsha256k128n96tau96v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k128n96tau96v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k128n96tau96v2/sse4/api.h"
#endif
#endif

#ifdef omdsha256k192n104tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha256k192n104tau128v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k192n104tau128v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k192n104tau128v2/sse4/api.h"
#endif
#endif

#ifdef omdsha256k256n104tau160v2
#ifdef avx1
#include "../crypto_aead/omdsha256k256n104tau160v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k256n104tau160v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k256n104tau160v2/sse4/api.h"
#endif
#endif

#ifdef omdsha256k256n248tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha256k256n248tau256v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha256k256n248tau256v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha256k256n248tau256v2/sse4/api.h"
#endif
#endif

#ifdef omdsha512k128n128tau128v2
#ifdef avx1
#include "../crypto_aead/omdsha512k128n128tau128v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k128n128tau128v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k128n128tau128v2/sse4/api.h"
#endif
#endif

#ifdef omdsha512k256n256tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha512k256n256tau256v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k256n256tau256v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k256n256tau256v2/sse4/api.h"
#endif
#endif

#ifdef omdsha512k512n256tau256v2
#ifdef avx1
#include "../crypto_aead/omdsha512k512n256tau256v2/avx1/api.h"
#endif
#ifdef ref
#include "../crypto_aead/omdsha512k512n256tau256v2/ref/api.h"
#endif
#ifdef sse4
#include "../crypto_aead/omdsha512k512n256tau256v2/sse4/api.h"
#endif
#endif

#ifdef paeq128
#ifdef aesni
#include "../crypto_aead/paeq128/aesni/api.h"
#endif
#ifdef opt-win-aes
#include "../crypto_aead/paeq128/opt-win-aes/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq128/ref/api.h"
#endif
#endif

#ifdef paeq128t
#ifdef aesni
#include "../crypto_aead/paeq128t/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq128t/ref/api.h"
#endif
#endif

#ifdef paeq128tnm
#ifdef aesni
#include "../crypto_aead/paeq128tnm/aesni/api.h"
#endif
#ifdef opt-win-aes
#include "../crypto_aead/paeq128tnm/opt-win-aes/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq128tnm/ref/api.h"
#endif
#endif

#ifdef paeq160
#ifdef aesni
#include "../crypto_aead/paeq160/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq160/ref/api.h"
#endif
#endif

#ifdef paeq64
#ifdef aesni
#include "../crypto_aead/paeq64/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq64/ref/api.h"
#endif
#endif

#ifdef paeq80
#ifdef aesni
#include "../crypto_aead/paeq80/aesni/api.h"
#endif
#ifdef ref
#include "../crypto_aead/paeq80/ref/api.h"
#endif
#endif

#ifdef pi16cipher096v2
#ifdef ref
#include "../crypto_aead/pi16cipher096v2/ref/api.h"
#endif
#endif

#ifdef pi16cipher128v2
#ifdef ref
#include "../crypto_aead/pi16cipher128v2/ref/api.h"
#endif
#endif

#ifdef pi32cipher128v2
#ifdef ref
#include "../crypto_aead/pi32cipher128v2/ref/api.h"
#endif
#endif

#ifdef pi32cipher256v2
#ifdef ref
#include "../crypto_aead/pi32cipher256v2/ref/api.h"
#endif
#endif

#ifdef pi64cipher128v2
#ifdef ref
#include "../crypto_aead/pi64cipher128v2/ref/api.h"
#endif
#endif

#ifdef pi64cipher256v2
#ifdef ref
#include "../crypto_aead/pi64cipher256v2/ref/api.h"
#endif
#endif

#ifdef present80n6t4silcv2
#ifdef ref
#include "../crypto_aead/present80n6t4silcv2/ref/api.h"
#endif
#endif

#ifdef primatesv1ape120
#ifdef ref
#include "../crypto_aead/primatesv1ape120/ref/api.h"
#endif
#endif

#ifdef primatesv1ape80
#ifdef ref
#include "../crypto_aead/primatesv1ape80/ref/api.h"
#endif
#endif

#ifdef primatesv1gibbon120
#ifdef ref
#include "../crypto_aead/primatesv1gibbon120/ref/api.h"
#endif
#endif

#ifdef primatesv1gibbon80
#ifdef ref
#include "../crypto_aead/primatesv1gibbon80/ref/api.h"
#endif
#endif

#ifdef primatesv1hanuman120
#ifdef ref
#include "../crypto_aead/primatesv1hanuman120/ref/api.h"
#endif
#endif

#ifdef primatesv1hanuman80
#ifdef ref
#include "../crypto_aead/primatesv1hanuman80/ref/api.h"
#endif
#endif

#ifdef riverkeyakv2
#ifdef ARMv6M
#include "../crypto_aead/riverkeyakv2/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/riverkeyakv2/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/riverkeyakv2/AVR8/api.h"
#endif
#ifdef Bulldozer
#include "../crypto_aead/riverkeyakv2/Bulldozer/api.h"
#endif
#ifdef Haswell
#include "../crypto_aead/riverkeyakv2/Haswell/api.h"
#endif
#ifdef Nehalem
#include "../crypto_aead/riverkeyakv2/Nehalem/api.h"
#endif
#ifdef SandyBridge
#include "../crypto_aead/riverkeyakv2/SandyBridge/api.h"
#endif
#ifdef compact
#include "../crypto_aead/riverkeyakv2/compact/api.h"
#endif
#ifdef generic32
#include "../crypto_aead/riverkeyakv2/generic32/api.h"
#endif
#ifdef generic32lc
#include "../crypto_aead/riverkeyakv2/generic32lc/api.h"
#endif
#ifdef generic64
#include "../crypto_aead/riverkeyakv2/generic64/api.h"
#endif
#ifdef generic64lc
#include "../crypto_aead/riverkeyakv2/generic64lc/api.h"
#endif
#ifdef reference
#include "../crypto_aead/riverkeyakv2/reference/api.h"
#endif
#ifdef reference32bits
#include "../crypto_aead/riverkeyakv2/reference32bits/api.h"
#endif
#endif

#ifdef scream10v3
#ifdef neon
#include "../crypto_aead/scream10v3/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/scream10v3/ref/api.h"
#endif
#ifdef sse
#include "../crypto_aead/scream10v3/sse/api.h"
#endif
#endif

#ifdef scream12v3
#ifdef neon
#include "../crypto_aead/scream12v3/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/scream12v3/ref/api.h"
#endif
#ifdef sse
#include "../crypto_aead/scream12v3/sse/api.h"
#endif
#endif

#ifdef seakeyakv2
#ifdef ARMv6M
#include "../crypto_aead/seakeyakv2/ARMv6M/api.h"
#endif
#ifdef ARMv7M
#include "../crypto_aead/seakeyakv2/ARMv7M/api.h"
#endif
#ifdef AVR8
#include "../crypto_aead/seakeyakv2/AVR8/api.h"
#endif
#ifdef Bulldozer
#include "../crypto_aead/seakeyakv2/Bulldozer/api.h"
#endif
#ifdef Haswell
#include "../crypto_aead/seakeyakv2/Haswell/api.h"
#endif
#ifdef Nehalem
#include "../crypto_aead/seakeyakv2/Nehalem/api.h"
#endif
#ifdef SandyBridge
#include "../crypto_aead/seakeyakv2/SandyBridge/api.h"
#endif
#ifdef asmX86-64
#include "../crypto_aead/seakeyakv2/asmX86-64/api.h"
#endif
#ifdef asmX86-64shld
#include "../crypto_aead/seakeyakv2/asmX86-64shld/api.h"
#endif
#ifdef compact
#include "../crypto_aead/seakeyakv2/compact/api.h"
#endif
#ifdef generic32
#include "../crypto_aead/seakeyakv2/generic32/api.h"
#endif
#ifdef generic32lc
#include "../crypto_aead/seakeyakv2/generic32lc/api.h"
#endif
#ifdef generic64
#include "../crypto_aead/seakeyakv2/generic64/api.h"
#endif
#ifdef generic64lc
#include "../crypto_aead/seakeyakv2/generic64lc/api.h"
#endif
#ifdef reference32bits
#include "../crypto_aead/seakeyakv2/reference32bits/api.h"
#endif
#endif

#ifdef shellaes128v2d4n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d4n64/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d4n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d4n80/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d5n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d5n64/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d5n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d5n80/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d6n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d6n64/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d6n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d6n80/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d7n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d7n64/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d7n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d7n80/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d8n64
#ifdef ref
#include "../crypto_aead/shellaes128v2d8n64/ref/api.h"
#endif
#endif

#ifdef shellaes128v2d8n80
#ifdef ref
#include "../crypto_aead/shellaes128v2d8n80/ref/api.h"
#endif
#endif

#ifdef simonjambu128v2
#ifdef ref
#include "../crypto_aead/simonjambu128v2/ref/api.h"
#endif
#endif

#ifdef simonjambu64v2
#ifdef ref
#include "../crypto_aead/simonjambu64v2/ref/api.h"
#endif
#endif

#ifdef simonjambu96v2
#ifdef ref
#include "../crypto_aead/simonjambu96v2/ref/api.h"
#endif
#endif

#ifdef stribob192r2
#ifdef _8bit
#include "../crypto_aead/stribob192r2/_8bit/api.h"
#endif
#ifdef bitslice
#include "../crypto_aead/stribob192r2/bitslice/api.h"
#endif
#ifdef neon
#include "../crypto_aead/stribob192r2/neon/api.h"
#endif
#ifdef ref
#include "../crypto_aead/stribob192r2/ref/api.h"
#endif
#ifdef smaller
#include "../crypto_aead/stribob192r2/smaller/api.h"
#endif
#ifdef ssse3
#include "../crypto_aead/stribob192r2/ssse3/api.h"
#endif
#endif

#ifdef tiaoxinv2
#ifdef nim
#include "../crypto_aead/tiaoxinv2/nim/api.h"
#endif
#ifdef ref
#include "../crypto_aead/tiaoxinv2/ref/api.h"
#endif
#endif

#ifdef trivia0v2
#ifdef ref
#include "../crypto_aead/trivia0v2/ref/api.h"
#endif
#endif

#ifdef trivia128v2
#ifdef ref
#include "../crypto_aead/trivia128v2/ref/api.h"
#endif
#endif

#ifdef twine80n6t4clocv2
#ifdef ref
#include "../crypto_aead/twine80n6t4clocv2/ref/api.h"
#endif
#ifdef vperm
#include "../crypto_aead/twine80n6t4clocv2/vperm/api.h"
#endif
#endif


int main(int argc, char** argv){
	printf("Start testing\n");
	
	unsigned char ciphertext[4096];
	unsigned char plaintext[4096], plaintext2[4096];
	unsigned char ad[4096];
	unsigned char key[16];
	unsigned char npub[16];
	unsigned char nsec[16];
	unsigned char mac[16];
	unsigned long long  msglen, adlen, clen;    // msg, adlen, clen in bytes.
	
	int i = 0;
	int retval = 0;
	
	for (i = 0; i < 16; i++) key[i] = 0;
	for (i = 0; i < 16; i++) npub[i] = 0;
	for (i = 0; i < 16; i++) nsec[i] = 0;
	
	for (i = 0; i < 4096; i++) plaintext[i]  = i%256;
	for (i = 0; i < 4096; i++) plaintext2[i]  = 0;
	for (i = 0; i < 4096; i++) ciphertext[i] = 0;
	for (i = 0; i < 4096; i++) ad[i] = i%7;
	
	msglen = 1003;
	adlen = 1003;
	
	
	retval = crypto_aead_encrypt(
								 ciphertext , &clen,
								 plaintext, msglen,
								 ad, adlen,
								 nsec,
								 npub,
								 key
								 );
	printf("%d\n", retval);
	
	retval = crypto_aead_decrypt(
								 plaintext2, &msglen,
								 nsec,
								 ciphertext,clen,
								 ad,adlen,
								 npub,
								 key
								 );
	
	printf("plaintext1: \n");
	for( i = 0; i < msglen; i++) printf("%2x", plaintext[i]);
	printf("\nplaintext2: \n");
	for( i = 0; i < msglen; i++) printf("%2x", plaintext2[i]);
	
	printf("\n%d\n", retval);
	
	printf("The tag is: ");
	for( i = 0; i < 16; i++) printf("%2x", ciphertext[msglen+i]);
	
	
	return 0;
}



