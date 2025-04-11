import AdminLayout from "../adminLayout"
import UserTable from "./components/userTable"



function UserList(){
    return ( 
        <AdminLayout>
            <UserTable />
        </AdminLayout>
    )
}
export default UserList