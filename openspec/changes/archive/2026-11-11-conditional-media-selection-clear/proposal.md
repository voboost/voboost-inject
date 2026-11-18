# Conditional media selection clear

## Why

A stale catalog cleanup must not overwrite a newer media selection.

## What Changes

Clear a vanished media package through one authenticated runtime-owner comparison and commit. Keep the existing state namespace and bounded JNI request/reply transport.

