// Progressive enhancement for file inputs marked with `data-accumulate`.
//
// A native <input type="file" multiple> replaces its FileList every time the picker
// is reopened, so you cannot gather files from more than one folder. We keep an
// accumulating DataTransfer, merge each pick (and any drag-and-drop) into it, and
// assign it back to the input — so the ordinary form submission still carries every
// selected file and no server change is needed.
(function () {
  "use strict";

  function humanSize(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }

  function enhance(input) {
    const store = new DataTransfer();
    const list = document.createElement("ul");
    list.className = "filelist";
    input.insertAdjacentElement("afterend", list);

    const keyOf = (f) => f.name + "|" + f.size + "|" + f.lastModified;

    function sync() {
      input.files = store.files; // does not re-fire `change`
      render();
    }

    function add(files) {
      const have = new Set(Array.from(store.files).map(keyOf));
      for (const f of files) {
        if (!have.has(keyOf(f))) {
          store.items.add(f);
          have.add(keyOf(f));
        }
      }
      sync();
    }

    function removeAt(index) {
      const kept = Array.from(store.files).filter((_, i) => i !== index);
      store.items.clear();
      kept.forEach((f) => store.items.add(f));
      sync();
    }

    function render() {
      list.innerHTML = "";
      Array.from(store.files).forEach((f, i) => {
        const li = document.createElement("li");

        const name = document.createElement("span");
        name.className = "fname";
        name.textContent = f.name;

        const size = document.createElement("span");
        size.className = "fsize";
        size.textContent = humanSize(f.size);

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "fremove";
        remove.setAttribute("aria-label", "Remove " + f.name);
        remove.textContent = "×";
        remove.addEventListener("click", () => removeAt(i));

        li.append(name, size, remove);
        list.appendChild(li);
      });
    }

    // Each pick: capture the new selection, then merge it into the running store.
    input.addEventListener("change", () => add(Array.from(input.files)));

    // Drag-and-drop onto the surrounding field also adds files.
    const zone = input.closest(".field") || input.parentElement;
    if (zone) {
      ["dragenter", "dragover"].forEach((ev) =>
        zone.addEventListener(ev, (e) => {
          e.preventDefault();
          zone.classList.add("dragover");
        })
      );
      ["dragleave", "drop"].forEach((ev) =>
        zone.addEventListener(ev, (e) => {
          e.preventDefault();
          zone.classList.remove("dragover");
        })
      );
      zone.addEventListener("drop", (e) => {
        if (e.dataTransfer && e.dataTransfer.files.length) add(e.dataTransfer.files);
      });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("input[type=file][data-accumulate]").forEach(enhance);
  });
})();
