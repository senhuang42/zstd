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

static void printSeqs(ZSTD_Sequence* inSeqs, size_t inSeqsSize) {
    size_t totalBytes = 0;
    for (size_t i = 0 ; i < inSeqsSize; ++i) {
        totalBytes += inSeqs[i].litLength + inSeqs[i].matchLength;
        printf("i : %zu (of: %u ml: %u ll: %u  - rep: %u)\n", i, inSeqs[i].offset, inSeqs[i].matchLength, inSeqs[i].litLength, inSeqs[i].rep);
    }
    printf("total bytes: %zu\n", totalBytes);
}

/* Returns size of generatedSrc buffer, modifies generatedSequencesSize to the nb of generated sequences */
static size_t generateRandomSrcAndSequences(ZSTD_Sequence* generatedSequences, size_t* generatedSequencesSize,
                                            uint8_t* generatedSrc, FUZZ_dataProducer_t* producer,
                                            const void* literals, size_t literalsSize, size_t windowLog) {
    const uint8_t* ip = literals;
    const uint8_t* const iend = literals + literalsSize;
    uint8_t* op = generatedSrc;
    uint32_t bytesRead = 0;
    uint32_t bytesGenerated = 0;
    uint32_t rollingLitLength = 0;
    uint32_t generatedSrcSize = FUZZ_dataProducer_uint32Range(producer, 0, ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);
    uint32_t matchChanceFactor = FUZZ_dataProducer_uint32Range(producer, 1, 100);   /* 0.5% to 100% chance of creating a match per byte */

    printf("match chance factor: %u\n", matchChanceFactor);
    printf("literalsSize = %u\n", literalsSize);
    printf("wlog = %u\n", windowLog);
    printf("generated src size: %u\n", generatedSrcSize);
    srand(FUZZ_dataProducer_uint32(producer));
    while (bytesGenerated < generatedSrcSize && ip < iend) {
        uint32_t bytesLeft = generatedSrcSize - bytesGenerated;
        int shouldCreateMatch = bytesRead > 0 ?
            (rand() % matchChanceFactor == 0) && (bytesLeft >= ZSTD_MINMATCH_MIN)
          : 0;
        uint32_t offset;
        uint32_t matchLength;
        uint32_t litLength;

        FUZZ_ASSERT(bytesGenerated <= generatedSrcSize);
        if (!shouldCreateMatch) {
            /* Write out one literal byte if we're not creating a new match */
            *op = *ip;
            ++ip; ++op; ++bytesRead; ++bytesGenerated; ++rollingLitLength;
            continue;
        }

        /* Generate a random, valid match */
        offset = (rand() % (bytesGenerated)) + 1;   /* of in: [1, bytesGenerated] */
        if (offset > 1 << windowLog) {
            offset = 1 << windowLog;
        }
        matchLength = (rand() % (bytesLeft - ZSTD_MINMATCH_MIN + 1)) + ZSTD_MINMATCH_MIN; /* ml in: [ZSTD_MINMATCH_MIN, bytesLeft] */
        litLength = rollingLitLength;
        printf("Creating Seq: %u, %u, %u\n", offset, matchLength, litLength);
        ZSTD_Sequence seq = {offset, litLength, matchLength, 0};
        generatedSequences[(*generatedSequencesSize)++] = seq;

        printf("Decoding match\n");
        /* Decode the match into the generated buffer */
        for (uint32_t i = 0; i < matchLength; ++i) {
            op[i] = op[(int)i - (int)offset];
        }
        op += matchLength;
        bytesGenerated += matchLength;
        rollingLitLength = 0;
    }
    printf("bytesGenerated: %u limilt : %u\n", bytesGenerated, generatedSrcSize);
    FUZZ_ASSERT(bytesGenerated <= generatedSrcSize);
    printSeqs(generatedSequences, *generatedSequencesSize);

    return bytesGenerated;
}

static size_t roundTripTest(void *result, size_t resultCapacity,
                            void *compressed, size_t compressedCapacity,
                            const void *src, size_t srcSize,
                            const ZSTD_Sequence* generatedSequences, size_t generatedSequencesSize,
                            FUZZ_dataProducer_t *producer)
{
    size_t cSize;
    size_t dSize;

    FUZZ_setRandomParameters(cctx, srcSize, producer);
    cSize = ZSTD_compressSequences(cctx, compressed, compressedCapacity,
                                   generatedSequences, generatedSequencesSize,
                                   src, srcSize, ZSTD_sf_noBlockDelimiters);
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
    void* generatedSrc;
    size_t generatedSrcSize;
    ZSTD_Sequence* generatedSequences;
    size_t generatedSequencesSize = 0;
    size_t wLog;

    /* Give a random portion of src data to the producer, to use for
    parameter generation. The rest will be used for (de)compression */
    FUZZ_dataProducer_t *producer = FUZZ_dataProducer_create(src, size);
    size = FUZZ_dataProducer_reserveDataPrefix(producer);

    wLog = FUZZ_dataProducer_uint32Range(producer, 0, ZSTD_WINDOWLOG_MAX);
    generatedSequences = FUZZ_malloc(sizeof(ZSTD_Sequence)*size);
    generatedSrc = FUZZ_malloc(ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);
    printf("Checkpoint 1\n");
    generatedSrcSize = generateRandomSrcAndSequences(generatedSequences, &generatedSequencesSize, generatedSrc, producer, src, size, wLog);

    printf("Checkpoint 2\n");
    cBufSize = ZSTD_compressBound(generatedSrcSize);
    cBuf = FUZZ_malloc(cBufSize);

    rBufSize = generatedSrcSize;
    rBuf = FUZZ_malloc(rBufSize);

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
            roundTripTest(rBuf, rBufSize, cBuf, cBufSize,
                          generatedSrc, generatedSrcSize,
                          generatedSequences, generatedSequencesSize,
                          producer);
        printf("Checkpoint 3\n");
        FUZZ_ZASSERT(result);
        FUZZ_ASSERT_MSG(result == generatedSrcSize, "Incorrect regenerated size");
        FUZZ_ASSERT_MSG(!FUZZ_memcmp(generatedSrc, rBuf, size), "Corruption!");
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
