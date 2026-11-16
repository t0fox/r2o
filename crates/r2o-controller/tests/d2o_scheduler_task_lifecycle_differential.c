/* C-оракул порядка терминальной жизни scheduler-задачи.
 *
 * Вызывает production task_reset/task_done/task_fail/d2k_sched_free из
 * core/sched.c на настоящих d2k_sched/task. Наблюдает:
 *   - терминальное событие (id/target/protocol/outcome/path/probe_units/
 *     elapsed/queue/ip/kind/shape/reason) и его однократность;
 *   - порядок: отчёт выдаётся до закрытия fd задачи;
 *   - закрытие contact/prop/ver/prop_bound/probe fd;
 *   - состояние слота после операции (T_FREE/T_RESTING, task_free_slot,
 *     d2k_sched_active);
 *   - join worker'а (s->workers_joined) до терминального отчёта;
 *   - порядок d2k_sched_free по слотам, а не по report_id;
 *   - счётчики madvise(MADV_DONTNEED) task_reset.
 *
 * stdout — строки event/state для diff с Rust. Файл из argv[1] — ресурсные
 * наблюдения C (fd, join, madvise), которые у Rust устроены иначе (RAII).
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sched.c"

static const char *trace_case = "";
static d2k_sched *trace_sched;
static int trace_reports;
static FILE *resources;
static unsigned long long free_report_ids[2];
static int free_slot_fds[2];
static unsigned long long free_joined_at_report[2];
static const char *free_slot_state[2];

static int fd_is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }

static const char *state_name(task_state state) {
    switch (state) {
    case T_FREE: return "T_FREE";
    case T_QUEUED: return "T_QUEUED";
    case T_ASKING: return "T_ASKING";
    case T_SHAPE_WAIT: return "T_SHAPE_WAIT";
    case T_PROPS_CONTACT: return "T_PROPS_CONTACT";
    case T_PROPS_WAIT: return "T_PROPS_WAIT";
    case T_PLANNING: return "T_PLANNING";
    case T_TRIAL_SETTLE: return "T_TRIAL_SETTLE";
    case T_VERIFY: return "T_VERIFY";
    case T_VERIFY_WAIT: return "T_VERIFY_WAIT";
    case T_WATCHING: return "T_WATCHING";
    case T_RESTING: return "T_RESTING";
    case T_VOICE_MEASURE: return "T_VOICE_MEASURE";
    case T_VOICE_TRIAL: return "T_VOICE_TRIAL";
    case T_VOICE_WATCH: return "T_VOICE_WATCH";
    case T_DNS_HEALTH: return "T_DNS_HEALTH";
    }
    return "T_UNKNOWN";
}

/* Наблюдатель видит задачу до закрытия fd: именно это и есть C-порядок
   search_report -> contact_close -> prop_close -> ver_close -> task_reset. */
static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    trace_reports++;
    printf("event case=%s seq=%d id=%llu target=%s protocol=%s family=%u "
           "trigger=%u outcome=%s path=%s probe_units=%lld elapsed_ms=%lld "
           "queue_ms=%lld ip=%s kind=%s shape=%u reason=%s\n",
           trace_case, trace_reports, (unsigned long long)event->id,
           event->target, event->protocol, event->family, event->trigger,
           event->outcome, event->path, (long long)event->probe_units,
           (long long)event->elapsed_ms, (long long)event->queue_ms, event->ip,
           event->kind, event->shape, event->reason);
    if (!resources) { return; }
    if (trace_sched && !strcmp(trace_case, "free")) {
        free_report_ids[trace_reports - 1] = (unsigned long long)event->id;
        free_slot_state[0] = state_name(trace_sched->tasks[0].state);
        free_slot_state[1] = state_name(trace_sched->tasks[1].state);
        free_joined_at_report[trace_reports - 1] = trace_sched->workers_joined;
        free_slot_fds[trace_reports - 1] =
            fd_is_open(trace_sched->tasks[0].c_fd) ||
            fd_is_open(trace_sched->tasks[0].prop_fd) ||
            fd_is_open(trace_sched->tasks[1].c_fd) ||
            fd_is_open(trace_sched->tasks[1].prop_fd);
        return;
    }
    if (trace_sched) {
        const task *task = &trace_sched->tasks[0];
        fprintf(resources,
                "C_ATREPORT case=%s slot0_fds=c%d,prop%d,ver%d,bound%d,probe%d "
                "state=%s joined=%llu\n",
                trace_case, fd_is_open(task->c_fd), fd_is_open(task->prop_fd),
                fd_is_open(task->ver.fd), fd_is_open(task->prop_bound_fd),
                fd_is_open(task->probe_fd), state_name(task->state),
                (unsigned long long)trace_sched->workers_joined);
    }
}

static void init_sched(d2k_sched *sched) {
    memset(sched, 0, sizeof *sched);
    sched->wake[0] = -1;
    sched->wake[1] = -1;
    sched->now_ms = 100000;
    sched->clock_seen = 1;
    sched->link_fd = -1;
    sched->diagnostic = observe;
    if (pthread_mutex_init(&sched->mu, NULL) != 0) { exit(1); }
    if (pthread_cond_init(&sched->question_cv, NULL) != 0) { exit(1); }
}

/* Ноль у task.prop_fd/probe_fd/ver.fd/c_fd значит «поле не трогали», а не
   «дескриптор 0»: production-код это учитывает, фикстура обязана тоже. */
static void init_task(task *task, int index, const char *host, const char *ip,
                      uint8_t transport, uint8_t shape, int probes, int ask,
                      int64_t elapsed, int64_t queue, const char *reason) {
    memset(task, 0, sizeof *task);
    task->prop_fd = -1;
    task->prop_q = -1;
    task->probe_fd = -1;
    task->ver.fd = -1;
    task->c_fd = -1;
    task->prop_bound_fd = -1;
    task->worker_started_ms = -1;
    snprintf(task->name, sizeof task->name, "%s", host);
    snprintf(task->ip, sizeof task->ip, "%s", ip);
    task->transport = transport;
    task->family = 4;
    task->trigger_shape = shape;
    task->state = T_ASKING;
    task->probes = probes;
    task->ask_probes = ask;
    task->report_id = (uint64_t)index;
    task->trigger_code = (uint8_t)index;
    task->trigger_flow.family = 4;
    task->report_admitted_ms = 100000 - elapsed;
    task->report_queue_ms = queue;
    snprintf(task->res.reason, sizeof task->res.reason, "%s", reason);
}

static int open_fd(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("open /dev/null"); exit(1); }
    return fd;
}

static void *idle_thread(void *argument) {
    (void)argument;
    return NULL;
}

static void arm_worker(d2k_sched *sched, task *task) {
    if (pthread_create(&task->th, NULL, idle_thread, NULL) != 0) { exit(1); }
    task->th_live = 1;
    task->worker_owner = sched;
    task->worker_started_ms = sched->now_ms - 500;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        resources = fopen(argv[1], "w");
        if (!resources) { perror("fopen resources"); return 2; }
    }
    d2k_diag_memory_enable(1);

    d2k_sched *sched = calloc(1, sizeof *sched);
    if (!sched) { return 1; }
    init_sched(sched);

    /* 1. task_reset: local-abort, только bound/probe fd, слот снова свободен. */
    trace_case = "reset";
    trace_sched = sched;
    trace_reports = 0;
    task *task = &sched->tasks[0];
    init_task(task, 1, "abort.example", "198.51.100.60", 6, 1, 5, 3, 1000,
              200, "локальный сброс");
    int bound_fd = open_fd();
    int probe_fd = open_fd();
    task->prop_bound_fd = bound_fd;
    task->probe_fd = probe_fd;
    d2k_sched_diagnostic_madvise_reset(sched);
    task_reset(sched, task);
    int bound_closed = !fd_is_open(bound_fd);
    int probe_closed = !fd_is_open(probe_fd);
    close(bound_fd);
    close(probe_fd);
    printf("state case=reset reports=%d state=%s worker_live=%d active=%zu "
           "slot_free=%d open_report=%d rest_ms=%lld\n",
           trace_reports, task->state == T_FREE ? "FREE" : state_name(task->state),
           task->th_live, d2k_sched_active(sched), task_free_slot(sched) == task,
           task->report_id && !task->report_closed,
           task->rest_until_ms > sched->now_ms
               ? (long long)(task->rest_until_ms - sched->now_ms)
               : 0LL);
    if (resources) {
        const d2k_diag_madvise *madvise = &sched->madvise;
        fprintf(resources,
                "C_RESET bound_closed=%d probe_closed=%d fd_after=%d,%d "
                "state_free=%d report_id_cleared=%d worker_started=%lld\n",
                bound_closed, probe_closed, task->prop_bound_fd,
                task->probe_fd, task->state == T_FREE, task->report_id == 0,
                (long long)task->worker_started_ms);
        fprintf(resources,
                "C_MADV active=%d task_bytes=%zu page=%ld requested_nonzero=%d "
                "successes=%llu failures=%llu "
                "failed_requested_nonzero=%d last_errno=%d hist=%d:%llu,%d:%llu,"
                "%d:%llu,%d:%llu other=%llu\n",
                d2k_diag_memory_active(), sizeof *task, sysconf(_SC_PAGESIZE),
                madvise->requested_bytes != 0,
                (unsigned long long)madvise->successes,
                (unsigned long long)madvise->failures,
                madvise->failed_requested_bytes != 0, madvise->last_errno,
                madvise->errno_hist[0].error,
                (unsigned long long)madvise->errno_hist[0].count,
                madvise->errno_hist[1].error,
                (unsigned long long)madvise->errno_hist[1].count,
                madvise->errno_hist[2].error,
                (unsigned long long)madvise->errno_hist[2].count,
                madvise->errno_hist[3].error,
                (unsigned long long)madvise->errno_hist[3].count,
                (unsigned long long)madvise->other_errno_count);
    }

    /* 2. task_done: join -> cancelled -> contact/prop/ver -> task_reset -> T_FREE. */
    trace_case = "done";
    trace_reports = 0;
    init_task(task, 2, "cancelled.example", "198.51.100.61", 6, 1, 3, 1, 2000,
              300, "поиск отменён");
    int done_c = open_fd();
    int done_prop = open_fd();
    int done_ver = open_fd();
    int done_bound = open_fd();
    int done_probe = open_fd();
    task->c_fd = done_c;
    task->prop_fd = done_prop;
    task->ver.fd = done_ver;
    task->prop_bound_fd = done_bound;
    task->probe_fd = done_probe;
    arm_worker(sched, task);
    unsigned long long joined_before = sched->workers_joined;
    task_done(sched, task);
    unsigned long long joined_delta = sched->workers_joined - joined_before;
    int done_closed = !fd_is_open(done_c) && !fd_is_open(done_prop) &&
                      !fd_is_open(done_ver) && !fd_is_open(done_bound) &&
                      !fd_is_open(done_probe);
    close(done_c); close(done_prop); close(done_ver); close(done_bound);
    close(done_probe);
    printf("state case=done reports=%d state=%s worker_live=%d active=%zu "
           "slot_free=%d open_report=%d rest_ms=%lld\n",
           trace_reports, task->state == T_FREE ? "FREE" : state_name(task->state),
           task->th_live, d2k_sched_active(sched), task_free_slot(sched) == task,
           task->report_id && !task->report_closed,
           task->rest_until_ms > sched->now_ms
               ? (long long)(task->rest_until_ms - sched->now_ms)
               : 0LL);
    if (resources) {
        fprintf(resources,
                "C_DONE five_fds_closed=%d joined_delta=%llu state_free=%d "
                "slot_free=%d report_id_cleared=%d\n",
                done_closed, (unsigned long long)joined_delta,
                task->state == T_FREE, task_free_slot(sched) == task,
                task->report_id == 0);
    }

    /* 3. task_fail: join -> failed -> contact -> trial_retire -> prop/ver ->
       T_RESTING и срок отдыха; слот не свободен, планы сброшены. */
    trace_case = "fail";
    trace_reports = 0;
    init_task(task, 3, "failed.example", "198.51.100.62", 6, 1, 4, 2, 3000,
              400, "измерение без классификации");
    int fail_c = open_fd();
    int fail_prop = open_fd();
    int fail_ver = open_fd();
    int fail_bound = open_fd();
    int fail_probe = open_fd();
    task->c_fd = fail_c;
    task->prop_fd = fail_prop;
    task->ver.fd = fail_ver;
    task->prop_bound_fd = fail_bound;
    task->probe_fd = fail_probe;
    task->partial_valid = 1;
    task->n_plans = 2;
    task->next_plan = 1;
    task->fb_queue = 1;
    arm_worker(sched, task);
    joined_before = sched->workers_joined;
    task_fail(sched, task, sched->now_ms);
    joined_delta = sched->workers_joined - joined_before;
    int fail_closed = !fd_is_open(fail_c) && !fd_is_open(fail_prop) &&
                      !fd_is_open(fail_ver) && !fd_is_open(fail_bound) &&
                      !fd_is_open(fail_probe);
    close(fail_c); close(fail_prop); close(fail_ver); close(fail_bound);
    close(fail_probe);
    printf("state case=fail reports=%d state=%s worker_live=%d active=%zu "
           "slot_free=%d open_report=%d rest_ms=%lld\n",
           trace_reports, task->state == T_RESTING ? "RESTING" : state_name(task->state),
           task->th_live, d2k_sched_active(sched), task_free_slot(sched) == task,
           task->report_id && !task->report_closed,
           task->rest_until_ms > sched->now_ms
               ? (long long)(task->rest_until_ms - sched->now_ms)
               : 0LL);
    if (resources) {
        fprintf(resources,
                "C_FAIL five_fds_closed=%d joined_delta=%llu state_resting=%d "
                "rest_ms=%lld slot_free=%d n_plans=%zu next_plan=%zu "
                "fb_queue=%d partial_valid=%d\n",
                fail_closed, (unsigned long long)joined_delta,
                task->state == T_RESTING,
                (long long)(task->rest_until_ms - sched->now_ms),
                task_free_slot(sched) == task, task->n_plans, task->next_plan,
                task->fb_queue, task->partial_valid);
    }

    pthread_mutex_destroy(&sched->mu);
    pthread_cond_destroy(&sched->question_cv);
    free(sched);

    /* 4. d2k_sched_free: join слота до shutdown-отчёта; отчёты идут по слотам
       (9, затем 2), а не по возрастанию report_id; после — fd и wake закрыты. */
    d2k_sched *freeing = calloc(1, sizeof *freeing);
    if (!freeing) { return 1; }
    init_sched(freeing);
    int wake_pipe[2];
    if (pipe(wake_pipe) != 0) { return 1; }
    freeing->wake[0] = wake_pipe[0];
    freeing->wake[1] = wake_pipe[1];
    trace_case = "free";
    trace_sched = freeing;
    trace_reports = 0;
    init_task(&freeing->tasks[0], 9, "shutdown-a.example", "198.51.100.63", 6,
              1, 2, 1, 5000, 600, "остановка A");
    init_task(&freeing->tasks[1], 2, "shutdown-b.example", "198.51.100.64", 17,
              3, 3, 1, 6000, 700, "остановка B");
    /* Вторая задача — в очереди: d2k_sched_free обязан отчитаться и о ней. */
    freeing->tasks[1].state = T_QUEUED;
    freeing->tasks[1].queued_ms = freeing->now_ms;
    /* d2k_sched_free закрывает contact/prop/ver; probe_fd задачи к моменту
       освобождения принадлежит уже завершённому worker'у и здесь -1. */
    int free0_c = open_fd();
    int free0_prop = open_fd();
    int free0_ver = open_fd();
    int free1_c = open_fd();
    int free1_prop = open_fd();
    int free1_ver = open_fd();
    freeing->tasks[0].c_fd = free0_c;
    freeing->tasks[0].prop_fd = free0_prop;
    freeing->tasks[0].ver.fd = free0_ver;
    freeing->tasks[1].c_fd = free1_c;
    freeing->tasks[1].prop_fd = free1_prop;
    freeing->tasks[1].ver.fd = free1_ver;
    arm_worker(freeing, &freeing->tasks[0]);
    /* slot1 остаётся без worker'а: join_worker(0) не увеличивает счётчик. */
    freeing->tasks[1].th_live = 0;
    unsigned long long free_joined_before = freeing->workers_joined;
    d2k_sched_free(freeing);
    int free_all_closed = !fd_is_open(free0_c) && !fd_is_open(free0_prop) &&
                          !fd_is_open(free0_ver) && !fd_is_open(free1_c) &&
                          !fd_is_open(free1_prop) && !fd_is_open(free1_ver);
    int wake_closed = !fd_is_open(wake_pipe[0]) && !fd_is_open(wake_pipe[1]);
    close(free0_c); close(free0_prop); close(free0_ver);
    close(free1_c); close(free1_prop); close(free1_ver);
    close(wake_pipe[0]); close(wake_pipe[1]);
    printf("state case=free reports=%d freed=1\n", trace_reports);
    if (resources) {
        fprintf(resources,
                "C_FREE reports=%d ids=%llu,%llu states=%s,%s "
                "joined_at_reports=%llu,%llu "
                "joined_delta=%llu slot_fds_open_at_report=%d,%d fds_closed=%d "
                "wake_closed=%d\n",
                trace_reports,
                trace_reports > 0 ? free_report_ids[0] : 0,
                trace_reports > 1 ? free_report_ids[1] : 0,
                free_slot_state[0], free_slot_state[1],
                free_joined_at_report[0], free_joined_at_report[1],
                free_joined_at_report[trace_reports > 1 ? 1 : 0] -
                    free_joined_before,
                trace_reports > 0 ? free_slot_fds[0] : -1,
                trace_reports > 1 ? free_slot_fds[1] : -1,
                free_all_closed, wake_closed);
        fclose(resources);
    }
    return 0;
}
