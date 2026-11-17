(() => {
  const mobileToggle = document.querySelector('[data-menu-toggle]');
  const mobileMenu = document.getElementById('mobile-nav');
  if (mobileToggle && mobileMenu) {
    mobileToggle.addEventListener('click', () => {
      const opening = mobileMenu.hidden;
      mobileMenu.hidden = !opening;
      mobileToggle.setAttribute('aria-expanded', String(opening));
    });
  }
  const statusInput = document.querySelector('[data-status-input]');
  const statusPreview = document.getElementById('status-preview');
  if (statusInput && statusPreview) {
    const update = () => { statusPreview.textContent = statusInput.value.split('\n').find(x => x.trim()) || 'Sem status definido'; };
    statusInput.addEventListener('input', update);
    update();
  }
  const toast = document.getElementById('toast');
  let toastTimer;
  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 2700);
  }
  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async () => {
      const value = button.getAttribute('data-copy');
      try {
        await navigator.clipboard.writeText(value);
        showToast('Link copiado com sucesso.');
      } catch (_) {
        showToast('Não foi possível copiar. Selecione o endereço na barra do navegador.');
      }
    });
  });
})();
