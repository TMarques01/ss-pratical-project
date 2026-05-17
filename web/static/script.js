document.addEventListener("DOMContentLoaded", () => {

  const params = new URLSearchParams(window.location.search);
  const title = params.get("uploaded");

  if (title)
  {
      const container = document.getElementById("flash-container");
      if (container)
      {
          const li = document.createElement("li");
          li.className = "flash success";

          li.innerHTML = `Document uploaded: ${title}`;

          container.appendChild(li);
      }
  }

    const buttons = document.querySelectorAll(".details-btn");

    buttons.forEach(btn => {
        btn.addEventListener("click", () => {

            if (btn.dataset.url) {
                window.location.href = btn.dataset.url;
                return;
            }

            const title = btn.dataset.title;
            const details = document.getElementById("doc-details");
            details.style.display = "block";
            renderTitle(title);
        });
    });

    function renderTitle(title) {
      const el = document.getElementById("doc-title");
      updateField(el, title);
    }

    function updateField(element, value) {
      element.innerHTML = "Title: " + value;
    }

});