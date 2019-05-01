#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)           \
                                    \
static struct trace_event_call __used event_##call = {          \
    .class          = &event_class_##template,      \
    {                               \
        .tp         = &__tracepoint_##call,     \
    },                              \
    .event.funcs        = &trace_event_type_funcs_##template,   \
    .print_fmt      = print_fmt_##template,         \
    .flags          = TRACE_EVENT_FL_TRACEPOINT,        \
};                                  \
static struct trace_event_call __used                   \
__attribute__((section("_ftrace_events"))) *__event_##call = &event_##call



