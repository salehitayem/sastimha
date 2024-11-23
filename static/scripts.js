function changeStatus(clientId, newStatus) {
    const notes = document.getElementById(`notes-${clientId}`).value;
    fetch('/update_status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: clientId, status: newStatus, notes: notes })
    }).then(response => response.json()).then(data => {
        if (data.success) location.reload();
        else alert(data.message);
    });
}

function confirmDelete(clientId) {
    if (confirm("Are you sure you want to delete this client? This action cannot be undone.")) {
        fetch('/delete_client', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: clientId })
        }).then(response => response.json()).then(data => {
            if (data.success) {
                alert(data.message);
                location.reload();
            } else {
                alert(data.message);
            }
        });
    }
}
