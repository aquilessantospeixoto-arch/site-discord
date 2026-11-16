const field = document.getElementById("names");
const preview = document.getElementById("preview-status");
if (field && preview) {
  const update = () => {
    const firstLine = field.value.split(/\r?\n/).map(line => line.trim()).find(Boolean);
    preview.textContent = firstLine || "Sem mensagem de status";
  };
  field.addEventListener("input", update);
  update();
}
