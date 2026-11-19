using ApiVault.Infrastructure.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ApiVault.Infrastructure.Data.Migrations
{
    /// <summary>Single-vault model: each account owns exactly one vault.</summary>
    [DbContext(typeof(AppDbContext))]
    [Migration("20261119120000_SingleVaultPerUser")]
    public partial class SingleVaultPerUser : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(name: "IX_Vaults_UserId", table: "Vaults");
            migrationBuilder.CreateIndex(name: "IX_Vaults_UserId", table: "Vaults", column: "UserId", unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(name: "IX_Vaults_UserId", table: "Vaults");
            migrationBuilder.CreateIndex(name: "IX_Vaults_UserId", table: "Vaults", column: "UserId");
        }
    }
}
