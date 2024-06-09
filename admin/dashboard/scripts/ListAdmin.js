function DisplayAllAdmin() {
    console.log("Displaylist")
    HideAll()
    const data = localStorage.getItem("admindata")
    var adminObject = JSON.parse(data);
    let isapproved = document.getElementById("listadmin-isapproved")
    let isblocked = document.getElementById("listadmin-isblocked")
    let canupdate = document.getElementById("listadmin-canupdate")
    let candelete = document.getElementById("listadmin-candelete")
    let canalteradmin = document.getElementById("listadmin-canalteradmin")
    console.log(isapproved.checked)
    if (isapproved.checked) {
        isapproved = "TRUE"
    } else {
        isapproved = "FALSE"
    }

    if (isblocked.checked) {
        isblocked = "TRUE"
    } else {
        isblocked = "FALSE"
    }

    if (canupdate.checked) {
        canupdate = "TRUE"
    } else {
        canupdate = "FALSE"
    }

    if (candelete.checked) {
        candelete = "TRUE"
    } else {
        candelete = "FALSE"
    }

    if (canalteradmin.checked) {
        canalteradmin = "TRUE"
    } else {
        canalteradmin = "FALSE"
    }
    let fromdate = document.getElementById("listadmin-fromdate").value
    let todate = document.getElementById("listadmin-todate").value
    let searchby = document.getElementById("listadmin-searchby").value
    let searchvalue = document.getElementById("listadmin-searchvalue").value


    const formData = {
        token: adminObject.token,
        publickey: adminObject.publickey,
        noofdata:Number(document.getElementById("listadmin-pagenation").value),
        sortby: document.getElementById("listadmin-orderby").value,
        sortorder: Number(document.getElementById("listadmin-ordervalue").value),

        isapproved: isapproved,
        isblocked: isblocked,
        canupdate: canupdate,
        candelete: candelete,
        canalteradmin: canalteradmin
    }
    if (searchby && searchvalue) {
        formData["searchby"] = searchby
        formData["searchvalue"] = searchvalue
    }
    if (fromdate) {
        formData["fromdate"] = fromdate + "T00:00:00Z";
    }
    if (todate) {
        formData["todate"] = todate + "T00:00:00Z"

    }

    document.getElementById('workersnip').style.display = 'block';
    fetch("http://localhost:8080/listadmin", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error.message, "Error", 0);
                return
            }
            let html = ""
            document.querySelector('.worker-list-body').innerHTML = html;
            if (!data.result.data) {
                return
            }
     
           
            data.result.data.forEach((admin,index) => {

                html += `

            <tr class="candidates-list">
            <td class="title">
              <div class="thumb"> <img class="img-fluid"
                  src="data:image/jpeg;base64,${admin.image}" alt="">
              </div>
              <div class="candidate-list-details">
                <div class="candidate-list-info">
                  <div class="candidate-list-title customer">
                    <h5 class="mb-0"><a href="#">${admin.adminname.toUpperCase()}</a></h5>
                  </div>
                  <div class="candidate-list-option">
                    <ul class="list-unstyled">
                      <li><i class="fas fa-filter pr-1"></i>${admin.adminid}</li>
                    </ul>
                  </div>
                </div>
              </div>
            </td>
            <td class="candidate-list-favourite-time text-center"> <a
                class="candidate-list-favourite order-2 text-danger" href="#"></a>
              <span class="candidate-list-time order-1">${admin.email}</span></td>
            <td>
              <ul class="list-unstyled mb-0 d-flex justify-content-end">
        
               <li  onclick="displayObjectInPopup('${encodeURIComponent(JSON.stringify(admin))}')"><a class="text-danger" data-toggle="tooltip" title=""
              data-original-title="Delete"><i class="far fa-eye"></i></a></li>`
                if (adminObject.email != admin.email && admin.email != "mithuorganics@gmail.com") {
                    html += `<li  onclick="deleteWorker('${admin.email}');DisplayAllWorkers();recentPage = 'worker';"><a class="text-danger" data-toggle="tooltip" title=""
                data-original-title="Delete"><i class="far fa-edit"></i></a></li>`
                }
                if (adminObject.email != admin.email && admin.email != "mithuorganics@gmail.com") {
                    html += `<li  onclick="showConfirmation(DeleteAdmin,'Are you sure want to Delete admin with Email ${admin.email}','YES','NO','${admin.email}');"><a class="text-danger" data-toggle="tooltip" title=""
                data-original-title="Delete"><i class="far fa-trash-alt"></i></a></li>`
                }
                if (adminObject.email != admin.email && admin.email != "mithuorganics@gmail.com" && !admin.isblocked) {
                    html += `<li  onclick="showConfirmation(BlockorUnBlockAdmin,'Are you sure want to Block admin with Email ${admin.email}','YES','NO','${admin.email}','BLOCK');"><a class="text-danger" data-toggle="tooltip" title=""
                data-original-title="Delete"><i class="fas fa-ban"></i></a></li>`
                }
                if (adminObject.email != admin.email && admin.email != "mithuorganics@gmail.com" && admin.isblocked) {
                    html += `<li  onclick="showConfirmation(BlockorUnBlockAdmin,'Are you sure want to UnBlock admin with Email ${admin.email}','YES','NO','${admin.email}','UNBLOCK');"><a class="text-danger" data-toggle="tooltip" title=""
                data-original-title="Delete"><i class="fas fa-unlock-alt"></i></a></li>`
                }
                if (adminObject.email == "mithuorganics@gmail.com" && !admin.isapproved) {
                    html += `<li  onclick="showConfirmation(ApproveAdmin,'Are you sure want to Approve admin with Email ${admin.email}','YES','NO','${admin.email}');"><a class="text-danger" data-toggle="tooltip" title=""
                data-original-title="Delete"><i class="far fa-check-circle"></i></a></li>`
                }
                html += `
              </ul>
            </td>
          </tr>`;

            });
            document.getElementById("noofitems").innerHTML =`${data.result.data.length} of ${data.result.data.length}`
            document.querySelector('.worker-list-body').innerHTML = html;
        })
        .catch(error => {
            showToast(error, "Error", 0);
        });
}

DefaultListAdminSet()
function DefaultListAdminSet() {
    document.getElementById("listadmin-isapproved").checked = true
    document.getElementById("listadmin-isblocked").checked = false
    document.getElementById("listadmin-canupdate").checked = true
    document.getElementById("listadmin-candelete").checked = true
    document.getElementById("listadmin-canalteradmin").checked = true
    document.getElementById("listadmin-fromdate").value = ""
    document.getElementById("listadmin-todate").value = ""
    document.getElementById("listadmin-searchby").value = ""
    document.getElementById("listadmin-searchvalue").value = ""
}



