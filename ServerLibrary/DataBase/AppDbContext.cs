using BaseLibrary.Entites;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibrary.DataBase
{
    public class AppDbContext(DbContextOptions options) : DbContext(options)
    {
        public DbSet<Employee> Employees { get; set; }

        public DbSet<GeneralDepartment> GeneralDepartments { get; set; }

        public DbSet<Department> Departments { get; set; }

        public DbSet<Branch> Branches { get; set; }

        public DbSet<Town> Towns { get; set; }

        public DbSet<AppUser> AppUsers { get; set; }
    }
}
