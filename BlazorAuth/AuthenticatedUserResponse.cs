using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BlazorAuth
{
    public class AuthenticatedUserResponse
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string EmployeeNumber { get; set; }
        public string[] Roles { get; set; }
        public int? StatusCode { get; set; }
    }
}
