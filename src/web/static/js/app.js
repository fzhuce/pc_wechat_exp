// Component instances
const contactList = new ContactList(document.getElementById('contact-list'));
const messageList = new MessageBubble(document.getElementById('message-list'));
const pagination = new Pagination(document.getElementById('pagination-bar'));
const chatHeader = new ChatHeader(document.getElementById('chat-header'));
const filterBar = new FilterBar(document.getElementById('filter-bar'));
const groupInfo = new GroupInfo(document.getElementById('group-info-content'));

async function initApp() {
  // Mount all components (event delegation survives re-renders)
  contactList.mount();
  messageList.mount();
  pagination.mount();
  chatHeader.mount();
  filterBar.mount();
  groupInfo.mount();

  // Initialize filter-bar DOM (replaces static HTML with component elements)
  filterBar.render({ filters: Store.data.filters });

  // Wire Store events
  Store.on('contact-selected', (chatId) => selectContact(chatId));
  Store.on('contact-search', (q) => loadContacts(q));
  Store.on('filter-changed', () => { Store.data.pagination.page = 1; loadMessages(); });
  Store.on('message-expanded', handleMessageExpanded);
  Store.on('group-info-toggle', () => openGroupInfo());
  Store.on('pagination-action', (action) => {
    const pg = Store.data.pagination;
    const map = { first: 1, prev: pg.page - 1, next: pg.page + 1, last: pg.total_pages };
    const page = map[action];
    if (page >= 1 && page <= (pg.total_pages || 0)) { Store.data.pagination.page = page; loadMessages(); }
  });
  Store.on('pagination-go', (page) => {
    if (page >= 1 && page <= (Store.data.pagination.total_pages || 0)) { Store.data.pagination.page = page; loadMessages(); }
  });
  Store.on('pagination-jump-date', (val) => {
    Store.data.filters.dateStart = val;
    Store.data.filters.dateEnd = val;
    Store.data.pagination.page = 1;
    const ds = document.querySelector('#filter-bar .filter-date-start');
    const de = document.querySelector('#filter-bar .filter-date-end');
    if (ds) ds.value = val;
    if (de) de.value = val;
    loadMessages();
  });

  // Show loading and fetch contacts
  contactList.render({ contacts: [], loading: true });
  await loadContacts();

  // Auto-select contact from URL parameter (?contact=NAME)
  const qp = new URLSearchParams(window.location.search);
  const contactParam = qp.get('contact');
  if (contactParam) {
    const target = _findContactByName(contactParam);
    if (target) {
      await selectContact(target.id);
    }
  }
}

function _findContactByName(name) {
  if (!name || !Store.data.contacts.length) return null;
  const q = name.toLowerCase();
  // Exact match first
  let c = Store.data.contacts.find(c => c.name === name);
  if (c) return c;
  // Prefix match (e.g., "张" matches "张三")
  c = Store.data.contacts.find(c => c.name.startsWith(name));
  if (c) return c;
  // Substring match
  c = Store.data.contacts.find(c => c.name.includes(name));
  if (c) return c;
  // Case-insensitive
  return Store.data.contacts.find(c => c.name.toLowerCase().includes(q)) || null;
}

async function loadContacts(q) {
  Store.data.contactsLoading = true;
  contactList.render({ contacts: [], loading: true, searchQuery: q || '' });
  try {
    const data = await api.contacts(q || '');
    Store.data.contacts = data.contacts;
  } catch (e) { if (e.name !== 'AbortError') console.error(e); }
  finally {
    Store.data.contactsLoading = false;
    contactList.render({
      contacts: Store.data.contacts,
      activeId: Store.data.activeChat ? Store.data.activeChat.id : null,
      loading: false,
      searchQuery: q || ''
    });
  }
}

async function selectContact(chatId) {
  cancelPending();
  Store.data.activeChat = Store.data.contacts.find(c => c.id === chatId);
  Store.data.pagination.page = 1;
  Store.data.expandedMsg = null;
  if (Store.data.activeChat) {
    chatHeader.render({
      name: Store.data.activeChat.name,
      id: Store.data.activeChat.id,
      avatar_url: Store.data.activeChat.avatar_url,
      type: Store.data.activeChat.type,
      stats: ''
    });
  } else {
    chatHeader.render(null);
  }
  filterBar.resetFilters();
  closeGroupInfo();
  contactList.render({ contacts: Store.data.contacts, activeId: chatId, loading: false });
  showChatUI(true);
  showLoading();
  try {
    const s = await api.chatStats(chatId);
    const ds = s.date_range.start || '?', de = s.date_range.end || '?';
    chatHeader.updateStats(`${s.total_messages.toLocaleString()} 条消息 · ${ds} ~ ${de}`);
    filterBar.populateSenderFilter(s.sender_distribution);
  } catch (e) {
    if (e.name !== 'AbortError') {
      console.error(e);
      chatHeader.updateStats('统计加载失败');
      const se = document.querySelector('#filter-bar .filter-sender');
      if (se) se.innerHTML = '<option value="">全部发送者</option>';
    }
  }
  await loadMessages();
}

async function loadMessages() {
  if (!Store.data.activeChat) return;
  Store.data.loading = true;
  showLoading();
  try {
    const data = await api.messages({
      chat_id: Store.data.activeChat.id,
      page: Store.data.pagination.page,
      per_page: Store.data.pagination.perPage,
      start_date: Store.data.filters.dateStart || undefined,
      end_date: Store.data.filters.dateEnd || undefined,
      type: Store.data.filters.msgTypes || undefined,
      sender: Store.data.filters.sender || undefined,
      keyword: Store.data.filters.keyword || undefined,
    });
    if (data.error) throw new Error(data.error);
    Store.data.messages = data.messages;
    Store.data.pagination = data.pagination;
    Store.data.expandedMsg = null;
    messageList.render({ messages: Store.data.messages, expandedMsg: Store.data.expandedMsg });
    pagination.render(Store.data.pagination);
    document.getElementById('message-list').scrollTop = 0;
    const rc = document.querySelector('#filter-bar .filter-result-count');
    if (rc) rc.textContent = `找到 ${data.pagination.total.toLocaleString()} 条`;
  } catch (e) {
    if (e.name !== 'AbortError') {
      showError('加载消息失败: ' + e.message);
      const rc = document.querySelector('#filter-bar .filter-result-count');
      if (rc) rc.textContent = '';
      pagination.render({ page: 0, per_page: 0, total: 0, total_pages: 0 });
    }
  } finally { Store.data.loading = false; }
}

async function handleMessageExpanded(msgId) {
  if (Store.data.expandedMsg === msgId) { Store.data.expandedMsg = null; }
  else {
    const msg = Store.data.messages.find(m => m.id === msgId);
    if (msg && msg.msg_type !== 1) {
      const needDetail = !msg.xml_parsed || Object.keys(msg.xml_parsed).length === 0;
      const needMedia = !msg.media_info && (msg.msg_type === 3 || msg.msg_type === 43 || msg.msg_type === 6);
      if (needDetail || needMedia) {
        try {
          const detail = await api.messageDetail(msgId, Store.data.activeChat ? Store.data.activeChat.id : '');
          if (detail) {
            if (needDetail) { msg.xml_parsed = detail.xml_parsed; msg.content = detail.content; }
            if (needMedia && detail.media_info) { msg.media_info = detail.media_info; }
          }
        } catch (e) { /* keep existing */ }
      }
    }
    Store.data.expandedMsg = msgId;
  }
  const listEl = document.getElementById('message-list');
  const st = listEl.scrollTop;
  messageList.render({ messages: Store.data.messages, expandedMsg: Store.data.expandedMsg });
  listEl.scrollTop = st;
}

// Global functions for inline onclick handlers in HTML (backdrop close, gi-btn)
async function openGroupInfo() {
  if (!Store.data.activeChat || Store.data.activeChat.type !== 'group') return;
  const panel = document.getElementById('group-info-panel');
  const backdrop = document.getElementById('group-info-backdrop');
  if (!panel || !backdrop) return;
  panel.style.display = 'block';
  backdrop.style.display = 'block';
  groupInfo.el.innerHTML = '<div class="loading"><div class="loading-icon">⏳</div>加载群信息...</div>';
  try {
    const data = await api.groupInfo(Store.data.activeChat.id);
    data.display_name = Store.data.activeChat.name;
    groupInfo.render(data);
  } catch (e) {
    if (e.name !== 'AbortError' && groupInfo.el) {
      groupInfo.el.innerHTML = `<div class="error-msg">加载失败: ${escapeHtml(e.message)}</div>`;
    }
  }
}

function closeGroupInfo() {
  const panel = document.getElementById('group-info-panel');
  const backdrop = document.getElementById('group-info-backdrop');
  if (!panel || !backdrop) return;
  panel.style.display = 'none';
  backdrop.style.display = 'none';
}

document.addEventListener('DOMContentLoaded', initApp);
