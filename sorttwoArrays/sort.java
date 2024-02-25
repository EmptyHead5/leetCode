class solution
{
//     public void merge(int[] nums1,int m,int[] nums2,int n){
//     for(int i=o;i<n;i++)
//     {
//         nums1[m+i]=nums2[i];
//     }
//     Arrays.sort(nums1)
//     }
 //通过for方法，将两个数组相加
 //使用java内置方法 Arrays.sort对数组直接进行排序
public void merge(int[] nums1,int m,int[] nums2,int n)
{
    int k=m+n;
    int[] temp=new int[k];
    for(int index=0;nums1Index=0;nums2Index=0;index<k,index++)
    {
        if(nums1Index>m)
        {//如果nums1为此时为空，则直接添加nums2进入temp内
            temp[index]=nums2[nums2Index++];
        }
        else if(nums2Index>n)
        {//如果nums2为此时为空，则直接添加nums2进入temp内
            temp[index]=nums1[nums1Index++];
        }
        else if(nums1[nums1Index]<nums2[nums2Index])
        {//如果nums1内的元素小于nums2内的元素，则将此时的元素添加入temp内
            temp[index]=nums1[nums1Index++];
        }
        else
        {//如果nums2内的元素小于nums1内的元素，则将此时的元素添加入temp内
            tempe[index]=nums2[nums2Index++];
        }
        //符合提议，将所有元素都添加如nums1内，使用k=m+n，对nums1的长度做出限制
        for(int i=0;i<k;i++)
        {
            nums1[i]=temp[i];
        }
    }
}
 }
