proc widget_proxy {widget widget_command args} {

    set result [uplevel [linsert $args 0 $widget_command]]

    if {([lindex $args 0] in {insert replace delete})} {
        event generate $widget <<Change>> -when tail
    }

    return $result
}