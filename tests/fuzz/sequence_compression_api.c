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

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

static const unsigned repStartValue[3] = { 1, 4, 8 };

#define ZSTD_FUZZ_GENERATED_SRC_MAXSIZE (1 << 25) /* Allow up to 32MB generated data */
#define ZSTD_FUZZ_MATCHLENGTH_MAXSIZE (1 << 18) /* Allow up to 256KB matches */
#define ZSTD_FUZZ_GENERATED_LITERALS_MAXSIZE (1 << 16) /* Allow up to 64KB literals buffer */
#define ZSTD_FUZZ_GENERATED_DICT_MAXSIZE (1 << 18) /* Allow up to a 256KB dict */
#define ZSTD_FUZZ_GENERATE_REPCODES 0 /* Disabled repcode fuzzing for now */


static void printSeqs(ZSTD_Sequence* inSeqs, size_t inSeqsSize) {
    size_t totalBytes = 0;
    size_t matchPos = 0;
    for (size_t i = 0 ; i < inSeqsSize; ++i) {
        totalBytes += inSeqs[i].litLength + inSeqs[i].matchLength;
        matchPos += inSeqs[i].litLength;
        printf("i : %zu (of: %u ml: %u ll: %u  - rep: %u) - matchpos: %u\n", i, inSeqs[i].offset, inSeqs[i].matchLength, inSeqs[i].litLength, inSeqs[i].rep, matchPos);
        matchPos += inSeqs[i].matchLength;
    }
    printf("total bytes: %zu\n", totalBytes);
}


static void Util_writeFile(char* fileName, void* buffer, size_t size)
{
    FILE* f = fopen(fileName, "wb");
    fwrite(buffer, sizeof(char), size, f);
    fclose(f);
}

/* Make a pseudorandom string - don't need anything fancy since we don't
 * really care about the contents of the string
 */
static char *generatePseudoRandomString(char *str, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK1234567890!@#$^&*()_";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
    }
    return str;
}
/* Returns size of source buffer */
static size_t decodeSequences2(void* dst, const ZSTD_Sequence* generatedSequences, size_t nbSequences,
                            const void* literals, size_t literalsSize, const void* dict, size_t dictSize) {
    const uint8_t* ip = literals;
    const uint8_t* const iend = literals + literalsSize;
    uint8_t* op = dst;
    size_t generatedSrcBufferSize = 0;
    size_t bytesWritten = 0;

    /* Note that src is a literals buffer */
    for (size_t i = 0; i < nbSequences; ++i) {
        assert(generatedSequences[i].matchLength != 0);
        assert(generatedSequences[i].offset != 0);

        ZSTD_memcpy(op, ip, generatedSequences[i].litLength);
        bytesWritten += generatedSequences[i].litLength;
        op += generatedSequences[i].litLength;
        ip += generatedSequences[i].litLength;
        literalsSize -= generatedSequences[i].litLength;

        assert(generatedSequences[i].offset != 0);
        {
            int j = 0;
            for (; j < generatedSequences[i].matchLength; ++j) {
                op[j] = op[j-(int)generatedSequences[i].offset];
            }
            op += j;
            bytesWritten += j;
        }
    }
    generatedSrcBufferSize = bytesWritten;
    assert(ip <= iend);
    ZSTD_memcpy(op, ip, literalsSize);
    return generatedSrcBufferSize;
}

/* Returns size of source buffer */
static size_t decodeSequences(void* dst, const ZSTD_Sequence* generatedSequences, size_t nbSequences,
                              const void* literals, size_t literalsSize, const void* dict, size_t dictSize) {
    const uint8_t* ip = literals;
    const uint8_t* dictPtr = dict;
    const uint8_t* const iend = literals + literalsSize;
    uint8_t* op = dst;
    size_t generatedSrcBufferSize = 0;
    size_t bytesWritten = 0;

    /* Note that src is a literals buffer */
    for (size_t i = 0; i < nbSequences; ++i) {
        assert(generatedSequences[i].matchLength != 0);
        assert(generatedSequences[i].offset != 0);

        ZSTD_memcpy(op, ip, generatedSequences[i].litLength);
        bytesWritten += generatedSequences[i].litLength;
        op += generatedSequences[i].litLength;
        ip += generatedSequences[i].litLength;
        literalsSize -= generatedSequences[i].litLength;

        assert(generatedSequences[i].offset != 0);
        /* Copy over the match */
        {   size_t matchLength = generatedSequences[i].matchLength;
            int j = 0;
            int k = 0;
            if (dictSize != 0) {
                if (generatedSequences[i].offset > bytesWritten) {
                    printf("Dict offset: %u, bytesWritten: %u, ml: %u\n", generatedSequences[i].offset, bytesWritten, matchLength);
                    size_t offsetFromEndOfDict = generatedSequences[i].offset - bytesWritten;
                    for (; k < offsetFromEndOfDict && k < matchLength; ++k) {
                        op[k] = dictPtr[dictSize - offsetFromEndOfDict + k];
                    }
                    matchLength -= k;
                    op += k;
                    printf("Copied %u bytes from dict\n", k);
                }
            }
            for (; j < matchLength; ++j) {
                op[j] = op[j-(int)generatedSequences[i].offset];
            }
            printf("Copied %u bytes from src\n", j);
            op += j;
            assert(generatedSequences[i].matchLength == j + k);
            bytesWritten += generatedSequences[i].matchLength;
        }
    }
    generatedSrcBufferSize = bytesWritten;
    assert(ip <= iend);
    ZSTD_memcpy(op, ip, literalsSize);
    return generatedSrcBufferSize;
}

/* Returns nb sequences */
static size_t generateRandomSequences(ZSTD_Sequence* generatedSequences,
                                      uint8_t* generatedSrc, FUZZ_dataProducer_t* producer,
                                      const void* literals, size_t literalsSize, size_t windowLog,
                                      size_t dictSize) {
    uint32_t bytesGenerated = 0;
    uint32_t nbSeqGenerated = 0;
    uint32_t litLength;
    uint32_t litBound;
    uint32_t matchLength;
    uint32_t offset;
    uint32_t offsetBound;
    uint32_t repCode;
    uint32_t isFirstSequence = 1;

    while (bytesGenerated < ZSTD_FUZZ_GENERATED_SRC_MAXSIZE && !FUZZ_dataProducer_empty(producer)) {
        if (isFirstSequence) {
            litLength = FUZZ_dataProducer_uint32Range(producer, 1, literalsSize);
        } else {
            litLength = FUZZ_dataProducer_uint32Range(producer, 0, literalsSize);
        }
        literalsSize -= litLength;
        bytesGenerated += litLength;
        if (bytesGenerated > ZSTD_FUZZ_GENERATED_SRC_MAXSIZE)
            break;

        /* Disable repcode generation for now */
        offsetBound = min(1 << windowLog + dictSize, bytesGenerated + dictSize);
        offset = FUZZ_dataProducer_uint32Range(producer, 1, offsetBound);
        matchLength = FUZZ_dataProducer_uint32Range(producer, ZSTD_MINMATCH_MIN, ZSTD_FUZZ_MATCHLENGTH_MAXSIZE);
        bytesGenerated += matchLength;
        if (bytesGenerated > ZSTD_FUZZ_GENERATED_SRC_MAXSIZE)
            break;

        ZSTD_Sequence seq = {offset, litLength, matchLength, repCode};
        generatedSequences[nbSeqGenerated++] = seq;
        isFirstSequence = 0;
    }

    return nbSeqGenerated;
}

static size_t roundTripTest(void *result, size_t resultCapacity,
                            void *compressed, size_t compressedCapacity,
                            const void *src, size_t srcSize,
                            const void *dict, size_t dictSize,
                            const ZSTD_Sequence* generatedSequences, size_t generatedSequencesSize,
                            FUZZ_dataProducer_t *producer, size_t wLog, unsigned hasDict)
{
    size_t cSize;
    size_t dSize;
    unsigned cLevel = FUZZ_dataProducer_uint32Range(producer, ZSTD_minCLevel, ZSTD_maxCLevel);
    ZSTD_CDict* cdict = NULL;
    ZSTD_DDict* ddict = NULL;

    ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_nbWorkers, 0);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, cLevel);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, wLog);
    if (hasDict) {
        cdict = ZSTD_createCDict(dict, dictSize, cLevel);
        ZSTD_CCtx_refCDict(cctx, cdict);
    }

    cSize = ZSTD_compressSequences(cctx, compressed, compressedCapacity,
                                   generatedSequences, generatedSequencesSize,
                                   src, srcSize);
    FUZZ_ZASSERT(cSize);

    if (hasDict) {
        ddict = ZSTD_createDDict(dict, dictSize);
        ZSTD_DCtx_refDDict(dctx, ddict);
    }

    dSize = ZSTD_decompressDCtx(dctx, result, resultCapacity, compressed, cSize);
    FUZZ_ZASSERT(dSize);

    if (cdict) {
        ZSTD_freeCDict(cdict);
    }
    if (ddict) {
        ZSTD_freeDDict(ddict);
    }
    return dSize;
}

int LLVMFuzzerTestOneInput(const uint8_t *src, size_t size)
{
    void* rBuf;
    size_t rBufSize;
    void* cBuf;
    size_t cBufSize;
    void* generatedSrc;
    size_t generatedSrcSize;
    unsigned hasDict;
    ZSTD_Sequence* generatedSequences;
    size_t nbSequences;
    size_t wLog;
    char* literalsBuffer;
    size_t literalsSize;
    char* dictBuffer;
    size_t dictSize = 0;

    FUZZ_dataProducer_t *producer = FUZZ_dataProducer_create(src, size);
    literalsSize = FUZZ_dataProducer_uint32Range(producer, 1, ZSTD_FUZZ_GENERATED_LITERALS_MAXSIZE);
    literalsBuffer = FUZZ_malloc(literalsSize);
    literalsBuffer = generatePseudoRandomString(literalsBuffer, literalsSize);

    hasDict = FUZZ_dataProducer_int32Range(producer, 0, 1);
    if (hasDict) {
        dictSize = FUZZ_dataProducer_uint32Range(producer, 1, ZSTD_FUZZ_GENERATED_DICT_MAXSIZE);
        dictBuffer = FUZZ_malloc(dictSize);
        dictBuffer = generatePseudoRandomString(dictBuffer, dictSize);
        printf("HAS DICT: size: %u\n", dictSize);
    }
    
    // for now, generate window log first so we dont generate offsets too large
    wLog = FUZZ_dataProducer_uint32Range(producer, ZSTD_WINDOWLOG_MIN, ZSTD_WINDOWLOG_MAX);

    generatedSequences = FUZZ_malloc(sizeof(ZSTD_Sequence)*ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);
    generatedSrc = FUZZ_malloc(ZSTD_FUZZ_GENERATED_SRC_MAXSIZE);

    nbSequences = generateRandomSequences(generatedSequences, generatedSrc, producer, literalsBuffer, literalsSize, wLog, dictSize);
    printSeqs(generatedSequences, nbSequences);
    generatedSrcSize = decodeSequences(generatedSrc, generatedSequences, nbSequences, literalsBuffer, literalsSize, dictBuffer, dictSize);

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

    size_t const result =
        roundTripTest(rBuf, rBufSize, cBuf, cBufSize,
                        generatedSrc, generatedSrcSize,
                        dictBuffer, dictSize,
                        generatedSequences, nbSequences,
                        producer, wLog, hasDict);
    FUZZ_ZASSERT(result);
    FUZZ_ASSERT_MSG(result == generatedSrcSize, "Incorrect regenerated size");
    FUZZ_ASSERT_MSG(!FUZZ_memcmp(generatedSrc, rBuf, generatedSrcSize), "Corruption!");
    free(rBuf);
    free(cBuf);
    free(generatedSequences);
    free(generatedSrc);
    free(literalsBuffer);
    FUZZ_dataProducer_free(producer);
#ifndef STATEFUL_FUZZING
    ZSTD_freeCCtx(cctx); cctx = NULL;
    ZSTD_freeDCtx(dctx); dctx = NULL;
#endif
    return 0;
}
