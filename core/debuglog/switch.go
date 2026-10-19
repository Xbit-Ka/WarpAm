/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110: the switch of the debug mode.
 */

package debuglog

// On turns the whole debug mode on or off. With false the program behaves
// as if the mode did not exist: Start, Fire and Printf return at once and
// no file is written. A single feature is switched off in its own file,
// by the second argument of Register.
const On = true
