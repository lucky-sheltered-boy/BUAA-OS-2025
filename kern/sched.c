#include <env.h>
#include <pmap.h>
#include <printk.h>

/* Overview:
 *   Implement a round-robin scheduling to select a runnable env and schedule it using 'env_run'.
 *
 * Post-Condition:
 *   If 'yield' is set (non-zero), 'curenv' should not be scheduled again unless it is the only
 *   runnable env.
 *
 * Hints:
 *   1. The variable 'count' used for counting slices should be defined as 'static'.
 *   2. Use variable 'env_sched_list', which contains and only contains all runnable envs.
 *   3. You shouldn't use any 'return' statement because this function is 'noreturn'.
 */
void schedule(int yield) {
	static int clock = -1; // 当前时间片，从 0 开始计数
	clock++;
	static struct Env *last = NULL;
	struct Env *env; // 循环变量

	LIST_FOREACH (env, &env_edf_sched_list, env_edf_sched_link) {
		// 在这里对 env 进行操作
		if (clock == env->env_period_deadline) {
			env->env_period_deadline += env->env_edf_period;
			env->env_runtime_left = env->env_edf_runtime;
		}	
	}
	
	int env_id = -1;
	int deadline = 100000000;
	int flag = 0;
	struct Env *des = NULL;
	 LIST_FOREACH (env, &env_edf_sched_list, env_edf_sched_link) {
		if (env->env_runtime_left <= 0) {
			continue;
		}
		if (env->env_period_deadline < deadline || env->env_period_deadline == deadline && env->env_id < env_id) {
			flag = 1;
			deadline = env->env_period_deadline;
			env_id = env->env_id;
			des = env;
		}
	 }
	if (flag == 1 && des != NULL) {
		des->env_runtime_left--;
		env_run(des);
		return;
	}
	static int count = 0; // remaining time slices of current env
	struct Env *e = last;

	/* We always decrease the 'count' by 1.
	 *
	 * If 'yield' is set, or 'count' has been decreased to 0, or 'e' (previous 'curenv') is
	 * 'NULL', or 'e' is not runnable, then we pick up a new env from 'env_sched_list' (list of
	 * all runnable envs), set 'count' to its priority, and schedule it with 'env_run'. **Panic
	 * if that list is empty**.
	 *
	 * (Note that if 'e' is still a runnable env, we should move it to the tail of
	 * 'env_sched_list' before picking up another env from its head, or we will schedule the
	 * head env repeatedly.)
	 *
	 * Otherwise, we simply schedule 'e' again.
	 *
	 * You may want to use macros below:
	 *   'TAILQ_FIRST', 'TAILQ_REMOVE', 'TAILQ_INSERT_TAIL'
	 */
	/* Exercise 3.12: Your code here. */
	if (yield || count == 0 || e == NULL || e->env_status != ENV_RUNNABLE) {
		if (e != NULL && e->env_status == ENV_RUNNABLE) {
			TAILQ_REMOVE(&env_sched_list, e, env_sched_link);
			TAILQ_INSERT_TAIL(&env_sched_list, e, env_sched_link);
		}
		e = TAILQ_FIRST(&env_sched_list);
		if (e == NULL) {
			panic("schedule: no runnable envs\n");
		}
		count = e->env_pri;
	}
	count--;
	last = e;
	env_run(e);
}

