window.BENCHMARK_DATA = {
  "lastUpdate": 1794572996267,
  "repoUrl": "https://github.com/Brainwires/webrtc-rs-rtc",
  "entries": {
    "WebRTC-RS Criterion Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "joshguyette@yahoo.com",
            "name": "Josh Guyette",
            "username": "nightness"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "355ead82505164ad266731b5d04039a6151ad7e0",
          "message": "Merge pull request #3 from Brainwires/fix/benchmarks-on-push\n\nci(bench): bencher output so the push-to-master store step finds results",
          "timestamp": "2026-11-13T06:13:22-06:00",
          "tree_id": "ebe665cb87b7ee7eb1fd33f2d93fd0b02b542343",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/355ead82505164ad266731b5d04039a6151ad7e0"
        },
        "date": 1794572995584,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 39,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 181,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 168,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 27,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 94,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 185,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 200,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 47,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 48,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 67,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 236,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 161,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 248,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 251,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageType_Value",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsMessage",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_NewTransactionID",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 198,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 75,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_AddTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1937,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5938,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1247,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1271,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 236,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 260,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 397,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 342,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1029,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 843,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 36,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 252763,
            "range": "± 11979",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 282120,
            "range": "± 1168",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}