using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthSample.Models
{
    public class AuthContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public AuthContext(DbContextOptions<AuthContext> options)
            : base(options)
        {
            Database.EnsureCreated();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // добавляем роли
            Role adminRole = new Role { Id = 1, Name = IdentityRoles.Administrator };
            Role vipUserRole = new Role { Id = 2, Name = IdentityRoles.VipUser }; 

            modelBuilder.Entity<Role>().HasData(new Role[] { adminRole, vipUserRole });

            base.OnModelCreating(modelBuilder);
        }
    }
}
