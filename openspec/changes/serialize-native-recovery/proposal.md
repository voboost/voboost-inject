# Serialize native recovery

## Why

A restore marker checked before work cannot exclude a resident operation already in progress. Offline restoration and resident effects need one native serialization boundary.

## What changes

Introduce a stable private native operation lock for new installations. Resident effects, supervisor delivery, live PW and offline helpers use that lock and recheck durable fences. Existing installations without the protocol are not silently upgraded by creating a marker.
