-- Update recipes allergy BOOL
create function update_recipe_allergies()
returns trigger
language plpgsql
as $$
begin
    UPDATE recipes t1
    SET allergy = TRUE
    FROM recipe_ingredient t2
    WHERE t1.user_id = t2.user_id AND t1.id = t2.recipe_id AND t2.allergy = TRUE;
    RETURN NULL;
end;
$$;

create trigger allergy_recipe_update_trigger
after update on recipe_ingredient
for each row
execute function update_recipe_allergies();