// voice-player.js — Voice player singleton and transcription
// Manages audio playback with per-bubble progress bar and seeking.
// Provides VoicePlayer singleton for inline onclick handlers in message-bubble templates.

class VoicePlayerComponent {
  constructor() {
    this.activeMsgId = null;
    this.audio = null;
    this._interval = null;
    this._rate = 2.0;  // default 2x speed
  }

  get rate() { return this._rate; }

  setRate(msgId, rate) {
    this._rate = rate;
    if (this.audio) this.audio.playbackRate = rate;
    this._updateSpeedBtns(msgId, rate);
  }

  _updateSpeedBtns(msgId, rate) {
    const ctrl = document.getElementById('vp-ctrl-' + msgId);
    if (!ctrl) return;
    for (const b of ctrl.querySelectorAll('.vp-speed-btn')) {
      b.classList.toggle('active', parseFloat(b.dataset.rate) === rate);
    }
  }

  stop() {
    if (this._interval) { clearInterval(this._interval); this._interval = null; }
    if (this.audio) { this.audio.pause(); this.audio = null; }
    const prev = this.activeMsgId;
    this.activeMsgId = null;
    if (prev) { this._updateUI(prev, 'pause'); }
  }

  _updateUI(msgId, action) {
    const ctrl = document.getElementById('vp-ctrl-' + msgId);
    if (!ctrl) return;
    const btn = ctrl.querySelector('.vp-play-btn');
    const bar = ctrl.querySelector('.vp-bar-fill');
    const curEl = ctrl.querySelector('.vp-time-cur');
    const durEl = ctrl.querySelector('.vp-time-dur');
    if (action === 'play') {
      if (btn) btn.textContent = '⏸';
    } else if (action === 'pause') {
      if (btn) btn.textContent = '▶';
      if (bar) bar.style.width = '0%';
    } else if (action === 'ended') {
      if (btn) btn.textContent = '▶';
      if (bar) bar.style.width = '0%';
    }
    if (action === 'time' && this.audio) {
      if (bar && this.audio.duration) bar.style.width = (this.audio.currentTime / this.audio.duration * 100) + '%';
      if (curEl) curEl.textContent = this._fmt(this.audio.currentTime);
      if (durEl && this.audio.duration) durEl.textContent = this._fmt(this.audio.duration);
    }
  }

  _fmt(sec) {
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return m > 0 ? m + '′' + String(s).padStart(2, '0') + '″' : s + '″';
  }

  toggle(msgId, url) {
    if (this.activeMsgId === msgId) {
      if (this.audio && !this.audio.paused) {
        this.audio.pause();
        this._updateUI(msgId, 'pause');
      } else if (this.audio) {
        this.audio.play();
        this._updateUI(msgId, 'play');
      }
      return;
    }
    this.stop();
    this.activeMsgId = msgId;
    const a = new Audio(url);
    this.audio = a;
    a.preload = 'auto';
    a.playbackRate = this._rate;
    this._updateSpeedBtns(msgId, this._rate);
    const self = this;
    a.addEventListener('loadedmetadata', function() { self._updateUI(msgId, 'time'); });
    a.addEventListener('timeupdate', function() { self._updateUI(msgId, 'time'); });
    a.addEventListener('ended', function() { self.stop(); });
    a.addEventListener('error', function() {
      const dw = document.getElementById('voice-download');
      if (dw) { dw.href = url; dw.style.display = 'inline-block'; }
      self.stop();
    });
    a.play().then(function() {
      self._updateUI(msgId, 'play');
    }).catch(function() {
      const dw = document.getElementById('voice-download');
      if (dw) { dw.href = url; dw.style.display = 'inline-block'; }
      self.stop();
    });
  }

  seek(msgId, evt) {
    if (this.activeMsgId !== msgId || !this.audio || !this.audio.duration) return;
    const rect = evt.currentTarget.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (evt.clientX - rect.left) / rect.width));
    this.audio.currentTime = ratio * this.audio.duration;
  }

  playVoice(url) {
    const a = new Audio(url);
    a.play().catch(function() {});
  }

  async transcribeVoice(msgId, voiceUrl) {
    const resultEl = document.getElementById('vp-result-' + msgId);
    const btn = document.getElementById('vp-trans-btn-' + msgId);
    if (!resultEl || !btn) return;
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = '识别中...';
    resultEl.style.display = '';
    resultEl.textContent = '';
    try {
      const transcriber = window.WhisperTranscriber;
      if (!transcriber) {
        throw new Error('Whisper 模块未加载，请刷新页面后重试');
      }
      const text = await transcriber.transcribe(voiceUrl, function(progress) {
        resultEl.textContent = progress;
      });
      if (text) {
        resultEl.textContent = text;
        resultEl.className = 'vp-trans-result success';
      } else {
        resultEl.textContent = '未识别到语音内容';
        resultEl.className = 'vp-trans-result empty';
      }
    } catch (e) {
      const msg = e.message || String(e);
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
        resultEl.textContent = '识别失败: 网络连接失败，请检查网络后重试';
      } else {
        resultEl.textContent = '识别失败: ' + msg;
      }
      resultEl.className = 'vp-trans-result error';
    } finally {
      btn.disabled = false;
      btn.textContent = 'T';
    }
  }
}

// Singleton instance for inline onclick handlers in message-bubble templates
const VoicePlayer = new VoicePlayerComponent();
const transcribeVoice = (msgId, voicePath) => VoicePlayer.transcribeVoice(msgId, voicePath);
