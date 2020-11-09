/*
 * Copyright (c) 2016-2020, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

/**
 * This fuzz target performs a zstd round-trip test (compress & decompress),
 * compares the result with the original, and calls abort() on corruption.
 */

#define ZSTD_STATIC_LINKING_ONLY

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "fuzz_helpers.h"
#include "zstd_helpers.h"
#include "fuzz_data_producer.h"

static ZSTD_CCtx *cctx = NULL;
static ZSTD_DCtx *dctx = NULL;

#define ZSTD_FUZZ_GENERATED_SRC_MAXSIZE (1 << 22) /* Allow up to 4 MB generated data */

/* Returns size of generatedSrc buffer */
static size_t generateRandomSequences(ZSTD_Sequence* generatedSequences,
                                      uint8_t* generatedSrc,
                                      const void* literals, size_t literalsSize,
                                      const FUZZ_dataProducer_t* producer) {
    const uint8_t* ip = literals;
    const uint8_t* const iend = literals + literalsSize;
    uint8_t* op = generatedSrc;
    uint32_t bytesRead = 0;
    uint32_t bytesGenerated = 0;
    uint32_t rollingLitLength = 0;
    uint32_t generatedSrcSize = FUZZ_dataProducer_uint32Range(producer, 0, ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);
    uint32_t matchChanceFactor = FUZZ_dataProducer_uint32Range(producer, 1, 100);

    srand(FUZZ_dataProducer_int32(producer));
    while (bytesGenerated <= generatedSrcSize) {
        uint32_t bytesLeft = generatedSrcSize - bytesGenerated;
        int shouldCreateMatch = bytesRead ?
            (rand() % matchChanceFactor) && (bytesLeft >= ZSTD_MINMATCH_MIN)
          : 0;
        uint32_t offset;
        uint32_t matchLength;
        uint32_t litLength;

        FUZZ_ASSERT(bytesGenerated <= generatedSrcSize);
        FUZZ_ASSERT(ip <= iend);
        if (!shouldCreateMatch) {
            /* Write out one literal byte if we're not creating a new match */
            *op = *ip;
            ++ip; ++op; ++bytesRead; ++bytesGenerated; ++rollingLitLength;
            continue;
        }

        /* Generate a random, valid match */
        offset = (rand() % (bytesGenerated)) + 1;   /* of in: [1, bytesGenerated] */
        matchLength = (rand() % (bytesLeft - ZSTD_MINMATCH_MIN + 1)) + ZSTD_MINMATCH_MIN; /* ml in: [ZSTD_MINMATCH_MIN, bytesLeft] */
        litLength = rollingLitLength;

        /* Decode the match into the generated buffer */
        for (int i = 0; matchLength; ++i) {
            op[i] = op[i - offset];
        }
        op += matchLength;
        bytesGenerated += matchLength;
        rollingLitLength = 0;
    }
    FUZZ_ASSERT(bytesGenerated == generatedSrcSize);

    return generatedSrcSize;
}

static size_t roundTripTest(void *result, size_t resultCapacity,
                            void *compressed, size_t compressedCapacity,
                            const void *src, size_t srcSize,
                            FUZZ_dataProducer_t *producer)
{
    size_t cSize;
    size_t dSize;
    int targetCBlockSize = 0;
    if (FUZZ_dataProducer_uint32Range(producer, 0, 1)) {
        FUZZ_setRandomParameters(cctx, srcSize, producer);
        cSize = ZSTD_compress2(cctx, compressed, compressedCapacity, src, srcSize);
        FUZZ_ZASSERT(ZSTD_CCtx_getParameter(cctx, ZSTD_c_targetCBlockSize, &targetCBlockSize));
    } else {
      int const cLevel = FUZZ_dataProducer_int32Range(producer, kMinClevel, kMaxClevel);

        cSize = ZSTD_compressCCtx(
            cctx, compressed, compressedCapacity, src, srcSize, cLevel);
    }
    FUZZ_ZASSERT(cSize);
    dSize = ZSTD_decompressDCtx(dctx, result, resultCapacity, compressed, cSize);
    FUZZ_ZASSERT(dSize);
    return dSize;
}

int LLVMFuzzerTestOneInput(const uint8_t *src, size_t size)
{
    size_t rBufSize;
    void* rBuf;
    size_t cBufSize;
    void* cBuf;
    ZSTD_Sequence* generatedSequences;
    void* generatedSrc;
    size_t generatedSrcSize;
    size_t litSize;

    /* Give a random portion of src data to the producer, to use for
    parameter generation. The rest will be used for (de)compression */
    FUZZ_dataProducer_t *producer = FUZZ_dataProducer_create(src, size);
    size = FUZZ_dataProducer_reserveDataPrefix(producer);

    /* Generated our sequences */
    generatedSequences = FUZZ_malloc(sizeof(ZSTD_Sequence)*size);
    generatedSrc = FUZZ_malloc(ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);
    generatedSrcSize = generateRandomSequences(generatedSequences, generatedSrc, src, size, producer);

    cBufSize = compressBound(generatedSrcSize);
    cBuf = FUZZ_malloc(cBufSize);

    rBufSize = generatedSrcSize;
    rBuf = FUZZ_malloc(rBuf);

    if (!cctx) {
        cctx = ZSTD_createCCtx();
        FUZZ_ASSERT(cctx);
    }
    if (!dctx) {
        dctx = ZSTD_createDCtx();
        FUZZ_ASSERT(dctx);
    }

    {
        size_t const result =
            roundTripTest(rBuf, rBufSize, cBuf, cBufSize, generatedSrc, generatedSrcSize, producer);
        FUZZ_ZASSERT(result);
        FUZZ_ASSERT_MSG(result == size, "Incorrect regenerated size");
        FUZZ_ASSERT_MSG(!FUZZ_memcmp(src, rBuf, size), "Corruption!");
    }
    free(rBuf);
    free(cBuf);
    free(generatedSequences);
    free(generatedSrc);
    FUZZ_dataProducer_free(producer);
#ifndef STATEFUL_FUZZING
    ZSTD_freeCCtx(cctx); cctx = NULL;
    ZSTD_freeDCtx(dctx); dctx = NULL;
#endif
    return 0;
}
