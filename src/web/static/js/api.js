let currentController = null;

function cancelPending() {
  if (currentController) { currentController.abort(); }
  currentController = new AbortController();
  return currentController.signal;
}

async function fetchJSON(url, signal) {
  const resp = await fetch(url, { signal });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      if (body && body.error) msg = body.error;
    } catch (_) { /* use default status message */ }
    throw new Error(msg);
  }
  return resp.json();
}

const api = {
  contacts(q) {
    const signal = cancelPending();
    const params = q ? `?q=${encodeURIComponent(q)}` : '';
    return fetchJSON(`/api/contacts${params}`, signal);
  },
  messages(params) {
    const signal = cancelPending();
    const qs = new URLSearchParams();
    qs.set('chat_id', params.chat_id);
    if (params.page) qs.set('page', params.page);
    if (params.per_page) qs.set('per_page', params.per_page);
    if (params.start_date) qs.set('start_date', params.start_date);
    if (params.end_date) qs.set('end_date', params.end_date);
    if (params.type) qs.set('type', params.type);
    if (params.sender) qs.set('sender', params.sender);
    if (params.keyword) qs.set('keyword', params.keyword);
    return fetchJSON(`/api/messages?${qs.toString()}`, signal);
  },
  messageDetail(id, chatId) { const signal = cancelPending(); return fetchJSON(`/api/messages/${id}?chat_id=${encodeURIComponent(chatId||'')}`, signal); },
  chatStats(chatId) { const signal = cancelPending(); return fetchJSON(`/api/chat/${encodeURIComponent(chatId)}/stats`, signal); },
  chatDates(chatId) { const signal = cancelPending(); return fetchJSON(`/api/chat/${encodeURIComponent(chatId)}/dates`, signal); },
  groupInfo(chatId) { const signal = cancelPending(); return fetchJSON(`/api/chat/${encodeURIComponent(chatId)}/group-info`, signal); },
  mediaUrl(path) { return path ? `/api/media?path=${encodeURIComponent(path)}` : null; },
  hardlinkMediaUrl(mediaInfo, fallbackType, localId) {
    if (!mediaInfo || (!mediaInfo.local_path && !mediaInfo.md5)) return null;
    const md5 = encodeURIComponent(mediaInfo.md5 || '');
    const path = encodeURIComponent(mediaInfo.local_path || '');
    const fname = encodeURIComponent(mediaInfo.file_name || '');
    const mtype = mediaInfo.media_type || fallbackType || 0;
    let url = `/api/hardlink-media?md5=${md5}&path=${path}&type=${mtype}&file_name=${fname}`;
    if (localId) url += `&local_id=${localId}`;
    return url;
  },
  voiceUrl(mediaInfo, createTime, localId) {
    const path = (mediaInfo && mediaInfo.voice_path) || '';
    if (!path) return null;
    let url = `/api/voice?path=${encodeURIComponent(path)}`;
    if (createTime) url += `&create_time=${createTime}`;
    if (localId) url += `&local_id=${localId}`;
    return url;
  }
};
