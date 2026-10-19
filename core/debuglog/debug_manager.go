/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110, debug feature: the choices of the manager.
 *
 * When a tunnel is raised, the manager decides for every running tunnel
 * whether it stays or goes. The ordinary log only says why one stays.
 * This feature also writes why one goes, so a tunnel that disappeared
 * without a question can be traced to the rule that took it.
 *
 * Point: "start-decision" (raising string, other string, verdict string).
 */

package debuglog

import "fmt"

func init() {
	Register("manager", true, func() {
		Listen("start-decision", func(args ...any) {
			if len(args) < 3 {
				return
			}
			Printf("raise of %s: %s %s", fmt.Sprint(args[0]), fmt.Sprint(args[1]), fmt.Sprint(args[2]))
		})
	})
}
