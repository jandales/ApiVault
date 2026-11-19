using ApiVault.BusinessLayer.Validators;
using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;

namespace ApiVault.BusinessLayer.Implementation;

public class TagService(ITagRepository tags) : ITagService
{
    public async Task<IReadOnlyList<TagDto>> ListAsync(string userId) =>
        (await tags.ListAsync(userId)).Select(t => new TagDto(t.Id, t.Name)).ToList();

    public async Task<ServiceResult<TagDto>> CreateAsync(string userId, TagRequest request)
    {
        var errors = SecretValidator.ValidateTagName(request.Name);
        if (errors.Count > 0) return ServiceResult<TagDto>.Fail(ErrorKind.Validation, "Invalid tag.", errors);

        var name = request.Name.Trim();
        if (await tags.NameExistsAsync(userId, name, null))
            return ServiceResult<TagDto>.Fail(ErrorKind.Conflict, "A tag with this name already exists.");

        var tag = new Tag { Id = Guid.NewGuid(), UserId = userId, Name = name, CreatedAt = DateTime.UtcNow };
        tags.Add(tag);
        await tags.SaveChangesAsync();
        return ServiceResult<TagDto>.Ok(new TagDto(tag.Id, tag.Name));
    }

    public async Task<ServiceResult<TagDto>> RenameAsync(string userId, Guid tagId, TagRequest request)
    {
        var errors = SecretValidator.ValidateTagName(request.Name);
        if (errors.Count > 0) return ServiceResult<TagDto>.Fail(ErrorKind.Validation, "Invalid tag.", errors);

        var tag = await tags.GetOwnedAsync(tagId, userId);
        if (tag is null) return ServiceResult<TagDto>.Fail(ErrorKind.NotFound, "Tag not found.");

        var name = request.Name.Trim();
        if (await tags.NameExistsAsync(userId, name, tagId))
            return ServiceResult<TagDto>.Fail(ErrorKind.Conflict, "A tag with this name already exists.");

        tag.Name = name;
        await tags.SaveChangesAsync();
        return ServiceResult<TagDto>.Ok(new TagDto(tag.Id, tag.Name));
    }

    public async Task<ServiceResult<bool>> DeleteAsync(string userId, Guid tagId)
    {
        var tag = await tags.GetOwnedAsync(tagId, userId);
        if (tag is null) return ServiceResult<bool>.Fail(ErrorKind.NotFound, "Tag not found.");
        await tags.RemoveAsync(tag);
        return ServiceResult<bool>.Ok(true);
    }
}
