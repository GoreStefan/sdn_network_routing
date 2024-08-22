    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        """Switch leave event handler"""
        msg = ev.switch.to_dict()
        self._rpc_broadcall('event_switch_leave', msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        """Link add event handler"""
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_add', msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        """Link delete event handler"""
        print("event delete")
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_delete', msg)

@set_ev_cls(event.EventHostAdd)
def _event_host_add_handler(self, ev):
    """Host add event handler"""
    msg = ev.host.to_dict()
    self._rpc_broadcall('event_host_add', msg)