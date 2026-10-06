// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

// What the external tests of the package drive by hand rather than through
// Run's tickers.

// Start marks the family as running, as Run does.
func (f *Family) Start() { f.start() }

// Stop reads the map a last time and stops reading it, as Run does on
// return.
func (f *Family) Stop() { f.stop() }

// CheckNewKeys runs one new-key check, as Run does every NewKeyInterval.
func (f *Family) CheckNewKeys() { f.checkNewKeys() }
