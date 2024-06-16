function CreateAdmin(event){
    event.preventDefault();
    const data = localStorage.getItem("admindata");
    var adminObject = JSON.parse(data);
    const formData = {
        fromadmintoken: adminObject.token,
        formadminpublickey: adminObject.publickey,
        email: document.getElementById("admin-email").value,
        name:  document.getElementById("admin-name").value ,
        ip: "12.12.12.21" ||document.getElementById("admin-ip").value,
        candelete:document.getElementById('admin-canupdate').checked,
        canupdate:document.getElementById('admin-candelete').checked,
        canalteradmin:document.getElementById('admin-canalteradmin').checked
    };
    console.log(formData)
    if(!formData.canalteradmin && !formData.candelete && !formData.canupdate){
        showToast("Please select any Previlages", "Error", 0);
        return
    }
    if(formData.name == "" || formData.name.length < 3){
        showToast("Please enter Valid Name", "Error", 0);
        return
    }
    if(validateEmail(formData.name)){
        showToast("Please enter Valid Email", "Error", 0);
        return
    }


    fetch("http://localhost:8080/createadmin", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
    })
        .then(response => response.json())
        .then(data => {
            if(data.error){
                showToast(data.error.message,"Error",0)
                return
            }
            showToast(data.result.message,"Success",3)
            document.getElementById("admin-email").value = ""
            document.getElementById("admin-name").value = ""
            document.getElementById('admin-canupdate').checked = false
            document.getElementById('admin-candelete').checked = false
            document.getElementById('admin-canalteradmin').checked = false
        })
        .catch(error => {
            showToast(error, "Error", 0);
        });
}