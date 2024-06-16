function DisplayAdminAudit() {
    console.log("DisplayAdminAudit")
    HideAll()
    
  
    const data = localStorage.getItem("admindata")
    var adminObject = JSON.parse(data);
  
    
    let fromdate = document.getElementById("listadminaudit-fromdate").value
    let todate = document.getElementById("listadminaudit-todate").value
    let searchby = document.getElementById("listadminaudit-searchby").value
    let searchvalue = document.getElementById("listadminaudit-searchvalue").value


    const formData = {
        token: adminObject.token,
        publickey: adminObject.publickey,
        noofdata:Number(document.getElementById("listadminaudit-pagenation").value),
        sortby: document.getElementById("listadminaudit-orderby").value,
        sortorder: Number(document.getElementById("listadminaudit-ordervalue").value),
        status:document.getElementById("listadminaudit-status").value
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
    document.getElementById("auditsnip").style.display = "block";
    console.log(formData)
    fetch("http://localhost:8080/listadminaudit", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
    })
        .then(response => response.json())
        .then(data => {
            console.log(data)
            if (data.error) {
                showToast(data.error.message, "Error", 0);
                return
            }
            let html = ""
            document.querySelector('.adminaudit-list-body').innerHTML = html;
            if (!data.result.data) {
                return
            }
     
           
            data.result.data.forEach((audit,index) => {

                html += `

            <tr class="candidates-list">
            <td class="title">
              <div class="candidate-list-details">
                <div class="candidate-list-info">
                  <div class="candidate-list-title customer">
                    <h5 class="mb-0"><a href="#">${audit.auditid}</a></h5>
                  </div>
                  <div class="candidate-list-option">
                    <ul class="list-unstyled">
                      <li><i class="fas fa-filter pr-1"></i>${audit.adminid}</li>
                    </ul>
                  </div>
                </div>
              </div>
            </td>
            <td class="candidate-list-favourite-time text-center"> <a
                class="candidate-list-favourite order-2 text-danger" href="#"></a>
              <span class="candidate-list-time order-1">${audit.message}</span></td>
            </td>

            <td class="candidate-list-favourite-time text-center"> <a
                class="candidate-list-favourite order-2 text-danger" href="#"></a>
              <span class="candidate-list-time order-1">${audit.statusmessage}</span></td>
            </td>
            <td>
              <ul class="list-unstyled mb-0 d-flex justify-content-end">
        
               <li  onclick="displayObjectInPopup('${encodeURIComponent(JSON.stringify(audit))}')"><a class="text-danger" data-toggle="tooltip" title=""
              data-original-title="Delete"><i class="far fa-eye"></i></a></li>
              
              </ul>
            </td>
          </tr>`;

            });
            
            document.getElementById("noofitemsinadminaudit").innerHTML =`${data.result.data.length} of ${data.result.data.length}`
            document.querySelector('.adminaudit-list-body').innerHTML = html;
        })
        .catch(error => {
            showToast(error, "Error", 0);
        });
}

DefaultAdminAuditSet()
function DefaultAdminAuditSet() {
    document.getElementById("listadminaudit-status").value = "ALL"
    document.getElementById("listadminaudit-fromdate").value = ""
    document.getElementById("listadminaudit-todate").value = ""
    document.getElementById("listadminaudit-searchby").value = ""
    document.getElementById("listadminaudit-searchvalue").value = ""
}



