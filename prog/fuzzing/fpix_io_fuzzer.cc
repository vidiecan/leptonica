/*
 * fpix_io_fuzzer: libFuzzer harness for the FPix / DPix serialized I/O
 * code path (fpixReadMem / dpixReadMem and the round-trip writers).
 *
 * The existing fpix2_fuzzer.cc seeds an FPix/DPix indirectly via
 * pixReadMemSpix() + pixConvertToDPix(), which never exercises the
 * text-header parser at the top of fpixReadStream() / dpixReadStream().
 * That parser:
 *   - reads "FPix Version <n>" / "DPix Version <n>"
 *   - fscanf("w = %d, h = %d, nbytes = %d", &w, &h, &nbytes)
 *   - rejects w<=0, h<=0, nbytes<0
 *   - rejects expected != (l_uint64)nbytes  where  expected = w*h*sizeof
 *   - then fgets()/sscanf() for xres/yres
 *   - then fread() of nbytes of binary float data
 * is exposed via the public LEPT_DLL extern fpixReadMem() / dpixReadMem()
 * symbols, so any consumer that deserialises FPix/DPix from an untrusted
 * byte buffer reaches this code. Cover it explicitly here.
 *
 * The harness:
 *   (1) feeds the raw fuzz buffer to fpixReadMem() and dpixReadMem(),
 *       exercising the header parser, size-consistency check, and
 *       binary read on attacker-controlled input;
 *   (2) when either read succeeds, round-trips through the matching
 *       Write/Read pair to also exercise the writer + a known-valid
 *       second read.
 */

#include "leptfuzz.h"

/* Cap input size to keep libFuzzer's per-input budget bounded.  fpix/dpix
 * binary payloads scale as 4*w*h or 8*w*h, so a few MB is more than enough
 * to reach every interesting code path. */
static const size_t kMaxInputSize = 4 * 1024 * 1024;

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > kMaxInputSize)
        return 0;

    leptSetStdNullHandler();

    /* ----- Path 1: fpixReadMem on the raw buffer ------------------ */
    FPIX *fpix_in = fpixReadMem(data, size);
    if (fpix_in) {
        l_uint8 *out_data = NULL;
        size_t   out_size = 0;
        if (fpixWriteMem(&out_data, &out_size, fpix_in) == 0 && out_data) {
            /* Round-trip the writer output through the reader to exercise
             * a known-valid byte stream as well as the parse path on a
             * second input. */
            FPIX *fpix_rt = fpixReadMem(out_data, out_size);
            fpixDestroy(&fpix_rt);
            lept_free(out_data);
        }
        fpixDestroy(&fpix_in);
    }

    /* ----- Path 2: dpixReadMem on the raw buffer ------------------ */
    DPIX *dpix_in = dpixReadMem(data, size);
    if (dpix_in) {
        l_uint8 *out_data = NULL;
        size_t   out_size = 0;
        if (dpixWriteMem(&out_data, &out_size, dpix_in) == 0 && out_data) {
            DPIX *dpix_rt = dpixReadMem(out_data, out_size);
            dpixDestroy(&dpix_rt);
            lept_free(out_data);
        }
        dpixDestroy(&dpix_in);
    }

    return 0;
}
